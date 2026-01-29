// pci_blockdev.c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/delay.h>

#include "pciblk_uapi.h"

#define DRV_NAME "pciblk_driver"

#define TESTDEV_VENDOR_ID   0x1B36
#define TESTDEV_PRODUCT_ID  0x0005

#define BAR_NUM     2
#define BAR_MASK    (1 << BAR_NUM)

/*
 * Вариант 8 (блочное устройство): в PDF перечислены поля, но не offsets.
 * Поэтому задаём карту регистров (можно поменять под твою реализацию QEMU/host-app):
 *
 * 0x00: RO storage_base  (u64)
 * 0x08: RO storage_size  (u64)
 * 0x10: RW doorbell/confirm (u64)  — и команды и статусы рукопожатия
 * 0x18: RO status (u32)
 * 0x20: RW xfer_buffer[...] (размер = max block size, например 4096)
 */
#define REG_STORAGE_BASE   0x00
#define REG_STORAGE_SIZE   0x08
#define REG_DOORBELL       0x10
#define REG_STATUS         0x18
#define REG_XFER_BUF       0x20

/*
 * Протокол (предложение, простое и рабочее):
 * doorbell (u64):
 *  bits 0..7   : flags
 *  bits 8..39  : length bytes (до 4K)  [32 бита хватит]
 *  bits 40..63 : reserved
 *
 * flags:
 *  BIT0 CMD_VALID
 *  BIT1 DIR_WRITE (1=write host/storage, 0=read)
 *  BIT2 DONE (device sets when completed)
 *  BIT3 ERR  (device sets on error)
 *
 * Адрес и block_size — храним в драйвере (через sysfs/ioctl), а device/host-app
 * должен читать их из sysfs? Нельзя. Поэтому для device нужна ещё доставка адреса.
 * Самый практичный вариант: кодируем адрес в первых 8 байтах xfer_buffer:
 *  xfer_buffer[0..7] = u64 addr
 *  xfer_buffer[8..]  = payload
 *
 * Тогда:
 *  write(): кладём addr + payload в xfer_buffer, пинаем doorbell CMD_VALID|DIR_WRITE
 *  read():  кладём addr в xfer_buffer[0..7], пинаем doorbell CMD_VALID (DIR_WRITE=0),
 *           ждём DONE, копируем payload из xfer_buffer[8..]
 */
#define DB_CMD_VALID  (1ULL << 0)
#define DB_DIR_WRITE  (1ULL << 1)
#define DB_DONE       (1ULL << 2)
#define DB_ERR        (1ULL << 3)

#define DEFAULT_BLOCK_SZ  4096
#define MAX_BLOCK_SZ      4096

static const u32 supported_block_sizes[] = { 1024, 2048, 4096 };

struct pciblk_dev {
	u8 __iomem *hw;
	resource_size_t hw_len;

	u64 addr;        /* текущий адрес (байты) */
	u32 block_sz;    /* текущий размер блока */

	struct mutex lock;

	struct device *dev;
	struct cdev cdev;
};

static int dev_major;
static struct class *pciblk_class;
static struct pciblk_dev g_dev; /* для простоты как в testdev */

/* -------- helpers -------- */

static bool is_supported_blksz(u32 v)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(supported_block_sizes); i++)
		if (supported_block_sizes[i] == v)
			return true;
	return false;
}

static inline u64 rd64(struct pciblk_dev *d, u32 off)
{
	return readq(d->hw + off);
}

static inline void wr64(struct pciblk_dev *d, u32 off, u64 v)
{
	writeq(v, d->hw + off);
}

static inline u32 rd32(struct pciblk_dev *d, u32 off)
{
	return readl(d->hw + off);
}

static int wait_done(struct pciblk_dev *d, unsigned long timeout_ms)
{
	unsigned long waited = 0;

	while (waited < timeout_ms) {
		u64 db = rd64(d, REG_DOORBELL);
		if (db & DB_DONE)
			return (db & DB_ERR) ? -EIO : 0;
		msleep(1);
		waited++;
	}
	return -ETIMEDOUT;
}

/* -------- sysfs -------- */

static ssize_t addr_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%llu\n", (unsigned long long)g_dev.addr);
}

static ssize_t addr_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	u64 v;
	if (kstrtou64(buf, 10, &v))
		return -EINVAL;

	mutex_lock(&g_dev.lock);
	g_dev.addr = v;
	mutex_unlock(&g_dev.lock);
	return count;
}
static DEVICE_ATTR_RW(addr);

static ssize_t block_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", g_dev.block_sz);
}

static ssize_t block_size_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	u32 v;
	if (kstrtou32(buf, 10, &v))
		return -EINVAL;
	if (!is_supported_blksz(v) || v > MAX_BLOCK_SZ)
		return -EINVAL;

	mutex_lock(&g_dev.lock);
	g_dev.block_sz = v;
	/* адрес должен быть выровнен */
	g_dev.addr = (g_dev.addr / v) * v;
	mutex_unlock(&g_dev.lock);
	return count;
}
static DEVICE_ATTR_RW(block_size);

static ssize_t supported_block_sizes_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int i;
	size_t n = 0;

	for (i = 0; i < ARRAY_SIZE(supported_block_sizes); i++)
		n += sysfs_emit_at(buf, n, "%u%s", supported_block_sizes[i],
				   (i + 1 == ARRAY_SIZE(supported_block_sizes)) ? "\n" : " ");
	return n;
}
static DEVICE_ATTR_RO(supported_block_sizes);

static ssize_t storage_base_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%llu\n",
			  (unsigned long long)rd64(&g_dev, REG_STORAGE_BASE));
}
static DEVICE_ATTR_RO(storage_base);

static ssize_t storage_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%llu\n",
			  (unsigned long long)rd64(&g_dev, REG_STORAGE_SIZE));
}
static DEVICE_ATTR_RO(storage_size);

static struct attribute *pciblk_attrs[] = {
	&dev_attr_addr.attr,
	&dev_attr_block_size.attr,
	&dev_attr_supported_block_sizes.attr,
	&dev_attr_storage_base.attr,
	&dev_attr_storage_size.attr,
	NULL,
};

static const struct attribute_group pciblk_attr_group = {
	.attrs = pciblk_attrs,
};

/* -------- file ops -------- */

static int pciblk_open(struct inode *inode, struct file *file)
{
	/* как в testdev: просто даём доступ к глобальному девайсу */
	file->private_data = &g_dev;
	return 0;
}

static int pciblk_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long pciblk_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pciblk_dev *d = file->private_data;

	switch (cmd) {
	case PCIBLK_IOC_SET_ADDR: {
		u64 v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v)))
			return -EFAULT;
		mutex_lock(&d->lock);
		if (d->block_sz && (v % d->block_sz)) {
			mutex_unlock(&d->lock);
			return -EINVAL;
		}
		d->addr = v;
		mutex_unlock(&d->lock);
		return 0;
	}
	case PCIBLK_IOC_GET_ADDR: {
		u64 v;
		mutex_lock(&d->lock);
		v = d->addr;
		mutex_unlock(&d->lock);
		if (copy_to_user((void __user *)arg, &v, sizeof(v)))
			return -EFAULT;
		return 0;
	}
	case PCIBLK_IOC_SET_BLKSZ: {
		u32 v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v)))
			return -EFAULT;
		if (!is_supported_blksz(v) || v > MAX_BLOCK_SZ)
			return -EINVAL;
		mutex_lock(&d->lock);
		d->block_sz = v;
		d->addr = (d->addr / v) * v;
		mutex_unlock(&d->lock);
		return 0;
	}
	case PCIBLK_IOC_GET_BLKSZ: {
		u32 v;
		mutex_lock(&d->lock);
		v = d->block_sz;
		mutex_unlock(&d->lock);
		if (copy_to_user((void __user *)arg, &v, sizeof(v)))
			return -EFAULT;
		return 0;
	}
	case PCIBLK_IOC_GET_INFO: {
		struct pciblk_info info;
		info.storage_base = rd64(d, REG_STORAGE_BASE);
		info.storage_size = rd64(d, REG_STORAGE_SIZE);
		if (copy_to_user((void __user *)arg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

static ssize_t pciblk_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct pciblk_dev *d = file->private_data;
	u64 addr;
	u32 bs;
	u64 storage_size;

	if (count == 0)
		return 0;

	mutex_lock(&d->lock);
	addr = d->addr;
	bs = d->block_sz;
	mutex_unlock(&d->lock);

	if (bs == 0)
		return -EINVAL;

	/* строго по блокам */
	if ((count % bs) != 0)
		return -EINVAL;

	if ((addr % bs) != 0)
		return -EINVAL;

	storage_size = rd64(d, REG_STORAGE_SIZE);
	if (addr + count > storage_size)
		return -EINVAL;

	mutex_lock(&d->lock);

	while (count) {
		/* положим addr в xfer_buffer[0..7] */
		writeq(addr, d->hw + REG_XFER_BUF);

		/* сброс DONE/ERR (если устройство так делает) — просто перезапишем doorbell */
		wr64(d, REG_DOORBELL, DB_CMD_VALID | ((u64)bs << 8)); /* DIR_WRITE=0 */

		if (wait_done(d, 5000)) { /* 5s */
			mutex_unlock(&d->lock);
			return -EIO;
		}

		/* читаем payload из xfer_buffer[8..8+bs) */
		if (copy_to_user(buf, (void __force *)(d->hw + REG_XFER_BUF + 8), bs)) {
			mutex_unlock(&d->lock);
			return -EFAULT;
		}

		addr += bs;
		buf += bs;
		count -= bs;
	}

	/* автосдвиг адреса */
	d->addr = addr;
	mutex_unlock(&d->lock);
	return 0; /* POSIX обычно ждёт bytes; но можно вернуть прочитанные bytes */
}

static ssize_t pciblk_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct pciblk_dev *d = file->private_data;
	u64 addr;
	u32 bs;
	u64 storage_size;

	if (count == 0)
		return 0;

	mutex_lock(&d->lock);
	addr = d->addr;
	bs = d->block_sz;
	mutex_unlock(&d->lock);

	if (bs == 0)
		return -EINVAL;

	if ((count % bs) != 0)
		return -EINVAL;

	if ((addr % bs) != 0)
		return -EINVAL;

	storage_size = rd64(d, REG_STORAGE_SIZE);
	if (addr + count > storage_size)
		return -EINVAL;

	mutex_lock(&d->lock);

	while (count) {
		/* addr в заголовок */
		writeq(addr, d->hw + REG_XFER_BUF);

		/* payload в xfer_buffer[8..] */
		if (copy_from_user((void __force *)(d->hw + REG_XFER_BUF + 8), buf, bs)) {
			mutex_unlock(&d->lock);
			return -EFAULT;
		}

		wr64(d, REG_DOORBELL, DB_CMD_VALID | DB_DIR_WRITE | ((u64)bs << 8));

		if (wait_done(d, 5000)) {
			mutex_unlock(&d->lock);
			return -EIO;
		}

		addr += bs;
		buf += bs;
		count -= bs;
	}

	d->addr = addr;
	mutex_unlock(&d->lock);

	return 0;
}

static const struct file_operations pciblk_fops = {
	.owner          = THIS_MODULE,
	.open           = pciblk_open,
	.release        = pciblk_release,
	.unlocked_ioctl = pciblk_ioctl,
	.read           = pciblk_read,
	.write          = pciblk_write,
};

/* -------- char dev create/destroy -------- */

static int create_char_dev(struct pciblk_dev *d)
{
	int err;
	dev_t dev;

	err = alloc_chrdev_region(&dev, 0, 1, "pciblk");
	if (err)
		return err;

	dev_major = MAJOR(dev);

	pciblk_class = class_create("pciblk");
	if (IS_ERR(pciblk_class)) {
		unregister_chrdev_region(MKDEV(dev_major, 0), 1);
		return PTR_ERR(pciblk_class);
	}

	cdev_init(&d->cdev, &pciblk_fops);
	d->cdev.owner = THIS_MODULE;

	err = cdev_add(&d->cdev, MKDEV(dev_major, 0), 1);
	if (err)
		goto fail_class;

	d->dev = device_create(pciblk_class, NULL, MKDEV(dev_major, 0), NULL, "pciblk");
	if (IS_ERR(d->dev)) {
		err = PTR_ERR(d->dev);
		goto fail_cdev;
	}

	err = sysfs_create_group(&d->dev->kobj, &pciblk_attr_group);
	if (err)
		goto fail_dev;

	return 0;

fail_dev:
	device_destroy(pciblk_class, MKDEV(dev_major, 0));
fail_cdev:
	cdev_del(&d->cdev);
fail_class:
	class_destroy(pciblk_class);
	unregister_chrdev_region(MKDEV(dev_major, 0), 1);
	return err;
}

static void destroy_char_dev(struct pciblk_dev *d)
{
	if (d->dev) {
		sysfs_remove_group(&d->dev->kobj, &pciblk_attr_group);
		device_destroy(pciblk_class, MKDEV(dev_major, 0));
		d->dev = NULL;
	}

	cdev_del(&d->cdev);

	if (pciblk_class) {
		class_destroy(pciblk_class);
		pciblk_class = NULL;
	}

	unregister_chrdev_region(MKDEV(dev_major, 0), 1);
}

/* -------- pci part -------- */

static struct pci_device_id pciblk_id_table[] = {
	{ PCI_DEVICE(TESTDEV_VENDOR_ID, TESTDEV_PRODUCT_ID) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pciblk_id_table);

static void release_device(struct pci_dev *pdev, int bar)
{
	pci_release_region(pdev, bar);
	pci_disable_device(pdev);
}

static int pciblk_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int bar_mask, err;
	resource_size_t mmio_start, mmio_len;

	bar_mask = pci_select_bars(pdev, IORESOURCE_MEM);
	if (!(bar_mask & BAR_MASK))
		return -ENODEV;

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	err = pci_request_region(pdev, BAR_NUM, DRV_NAME);
	if (err) {
		pci_disable_device(pdev);
		return err;
	}

	mmio_start = pci_resource_start(pdev, BAR_NUM);
	mmio_len   = pci_resource_len(pdev, BAR_NUM);

	memset(&g_dev, 0, sizeof(g_dev));
	mutex_init(&g_dev.lock);

	g_dev.hw_len = mmio_len;
	g_dev.hw = ioremap(mmio_start, mmio_len);
	if (!g_dev.hw) {
		release_device(pdev, BAR_NUM);
		return -EIO;
	}

	/* дефолты */
	g_dev.block_sz = DEFAULT_BLOCK_SZ;
	g_dev.addr     = 0;

	err = create_char_dev(&g_dev);
	if (err) {
		iounmap(g_dev.hw);
		release_device(pdev, BAR_NUM);
		return err;
	}

	pci_set_drvdata(pdev, &g_dev);

	pr_info("pciblk: mapped BAR%d @0x%llx len=0x%llx\n",
		BAR_NUM, (unsigned long long)mmio_start, (unsigned long long)mmio_len);

	return 0;
}

static void pciblk_remove(struct pci_dev *pdev)
{
	struct pciblk_dev *d = pci_get_drvdata(pdev);

	destroy_char_dev(d);

	if (d && d->hw)
		iounmap(d->hw);

	release_device(pdev, BAR_NUM);
}

static struct pci_driver pciblk_driver = {
	.name     = DRV_NAME,
	.id_table = pciblk_id_table,
	.probe    = pciblk_probe,
	.remove   = pciblk_remove,
};

static int __init pciblk_init(void)
{
	return pci_register_driver(&pciblk_driver);
}

static void __exit pciblk_exit(void)
{
	pci_unregister_driver(&pciblk_driver);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("PCI block-like char device (variant 8)");
MODULE_VERSION("0.1");

module_init(pciblk_init);
module_exit(pciblk_exit);
