// pcie_lab2_block.c — Lab2: PCIe char driver with block-aligned I/O (Variant 8)
//
// Behavior:
// - Exposes /dev/pcie_blk0 (char device), but enforces block alignment like a block device.
// - Read/write only in multiples of block_size, starting at LBA * block_size.
// - block_size, storage_size are read from BAR2 registers (file-backed in QEMU).
//
// BAR2 layout (example):
//   0x00 u64 storage_base   (RO) typically 0
//   0x08 u64 storage_size   (RO) bytes, must be multiple of block_size
//   0x10 u32 status         (RO) READY/ERROR bits
//   0x14 u32 block_size     (RO) bytes, e.g., 512 or 4096
//   0x100 data region       (RW) storage bytes
//
// sysfs (class pcie_blk):
//   /sys/class/pcie_blk/pcie_blk0/lba            RW
//   /sys/class/pcie_blk/pcie_blk0/block_size     RO
//   /sys/class/pcie_blk/pcie_blk0/storage_size   RO
//   /sys/class/pcie_blk/pcie_blk0/write_max      RW  (max bytes per write, must be multiple of block_size)
//
// ioctl:
//   SET_LBA / GET_LBA / GET_BS / GET_STORAGE_SIZE

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#define DRV_NAME     "pcie_lab2_block"
#define CLASS_NAME   "pcie_blk"

#define BAR_INDEX    2
#define DATA_OFFSET  0x100

// BAR2 register offsets
#define REG_STORAGE_BASE  0x00  // u64 RO
#define REG_STORAGE_SIZE  0x08  // u64 RO
#define REG_STATUS        0x10  // u32 RO
#define REG_BLOCK_SIZE    0x14  // u32 RO

#define STATUS_READY (1u << 0)
#define STATUS_ERROR (1u << 1)

// ioctl
#define PCIE_BLK_IOC_MAGIC          'b'
#define PCIE_BLK_IOC_SET_LBA        _IOW(PCIE_BLK_IOC_MAGIC, 1, __u64)
#define PCIE_BLK_IOC_GET_LBA        _IOR(PCIE_BLK_IOC_MAGIC, 2, __u64)
#define PCIE_BLK_IOC_GET_BS         _IOR(PCIE_BLK_IOC_MAGIC, 3, __u32)
#define PCIE_BLK_IOC_GET_STORAGESZ  _IOR(PCIE_BLK_IOC_MAGIC, 4, __u64)

struct pcie_blk_dev {
	struct pci_dev *pdev;
	void __iomem *bar;
	resource_size_t bar_len;

	dev_t devt;
	struct cdev cdev;
	struct class *class;
	struct device *device;

	struct mutex lock;

	/* device-reported */
	u64 storage_base;
	u64 storage_size;
	u32 block_size;

	/* runtime config */
	u64 lba;
	u32 write_max; /* bytes, must be multiple of block_size */
};

static struct pcie_blk_dev g_dev;

static inline u64 mmio_read64(void __iomem *base, u32 off)
{
#if BITS_PER_LONG == 64
	return readq(base + off);
#else
	u32 lo = readl(base + off);
	u32 hi = readl(base + off + 4);
	return ((u64)hi << 32) | lo;
#endif
}

static inline void mmio_read8_buf(u8 *dst, void __iomem *src, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		dst[i] = readb(src + i);
}

static inline void mmio_write8_buf(void __iomem *dst, const u8 *src, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		writeb(src[i], dst + i);
}

/* ---------- sysfs ---------- */

static ssize_t lba_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%llu\n", (unsigned long long)g_dev.lba);
}

static ssize_t lba_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	u64 v;
	if (kstrtou64(buf, 0, &v))
		return -EINVAL;

	mutex_lock(&g_dev.lock);
	g_dev.lba = v;
	mutex_unlock(&g_dev.lock);
	return count;
}
static DEVICE_ATTR_RW(lba);

static ssize_t block_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", g_dev.block_size);
}
static DEVICE_ATTR_RO(block_size);

static ssize_t storage_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%llu\n", (unsigned long long)g_dev.storage_size);
}
static DEVICE_ATTR_RO(storage_size);

static ssize_t write_max_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", g_dev.write_max);
}

static ssize_t write_max_store(struct device *dev, struct device_attribute *attr,
			       const char *buf, size_t count)
{
	u32 v;
	if (kstrtou32(buf, 0, &v))
		return -EINVAL;

	/* enforce block multiple (if block_size already known) */
	mutex_lock(&g_dev.lock);
	if (g_dev.block_size != 0 && (v % g_dev.block_size) != 0) {
		mutex_unlock(&g_dev.lock);
		return -EINVAL;
	}
	g_dev.write_max = v;
	mutex_unlock(&g_dev.lock);
	return count;
}
static DEVICE_ATTR_RW(write_max);

static struct attribute *pcie_blk_attrs[] = {
	&dev_attr_lba.attr,
	&dev_attr_block_size.attr,
	&dev_attr_storage_size.attr,
	&dev_attr_write_max.attr,
	NULL
};

static const struct attribute_group pcie_blk_attr_group = {
	.attrs = pcie_blk_attrs,
};

/* ---------- file ops ---------- */

static int pcie_blk_open(struct inode *inode, struct file *file)
{
	file->private_data = &g_dev;
	return 0;
}

static inline int check_ready(void __iomem *bar)
{
	u32 status = readl(bar + REG_STATUS);
	if (!(status & STATUS_READY))
		return -EAGAIN;
	if (status & STATUS_ERROR)
		return -EIO;
	return 0;
}

static ssize_t pcie_blk_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	struct pcie_blk_dev *d = file->private_data;
	u8 *kbuf;
	u64 lba, byte_off;
	u32 bs;
	int r;

	if (count == 0)
		return 0;

	r = check_ready(d->bar);
	if (r)
		return r;

	mutex_lock(&d->lock);
	lba = d->lba;
	bs  = d->block_size;
	mutex_unlock(&d->lock);

	/* strict block semantics */
	if (bs == 0)
		return -EINVAL;
	if (count % bs != 0)
		return -EINVAL;

	byte_off = lba * (u64)bs;
	if (byte_off + count > d->storage_size)
		return -EINVAL;

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	mmio_read8_buf(kbuf, d->bar + DATA_OFFSET + byte_off, count);

	if (copy_to_user(ubuf, kbuf, count)) {
		kfree(kbuf);
		return -EFAULT;
	}

	kfree(kbuf);
	return count;
}

static ssize_t pcie_blk_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct pcie_blk_dev *d = file->private_data;
	u8 *kbuf;
	u64 lba, byte_off;
	u32 bs, wmax;
	size_t to_write;
	int r;

	if (count == 0)
		return 0;

	r = check_ready(d->bar);
	if (r)
		return r;

	mutex_lock(&d->lock);
	lba  = d->lba;
	bs   = d->block_size;
	wmax = d->write_max;
	mutex_unlock(&d->lock);

	if (bs == 0)
		return -EINVAL;

	/* strict block semantics */
	if (count % bs != 0)
		return -EINVAL;

	to_write = count;
	if (wmax != 0 && to_write > wmax)
		to_write = wmax;

	/* still must be multiple of block size */
	to_write -= (to_write % bs);
	if (to_write == 0)
		return -EINVAL;

	byte_off = lba * (u64)bs;
	if (byte_off + to_write > d->storage_size)
		return -EINVAL;

	kbuf = kmalloc(to_write, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, ubuf, to_write)) {
		kfree(kbuf);
		return -EFAULT;
	}

	mmio_write8_buf(d->bar + DATA_OFFSET + byte_off, kbuf, to_write);
	kfree(kbuf);
	return to_write;
}

static long pcie_blk_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pcie_blk_dev *d = file->private_data;

	switch (cmd) {
	case PCIE_BLK_IOC_SET_LBA: {
		u64 v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v)))
			return -EFAULT;
		mutex_lock(&d->lock);
		d->lba = v;
		mutex_unlock(&d->lock);
		return 0;
	}
	case PCIE_BLK_IOC_GET_LBA: {
		u64 v;
		mutex_lock(&d->lock);
		v = d->lba;
		mutex_unlock(&d->lock);
		if (copy_to_user((void __user *)arg, &v, sizeof(v)))
			return -EFAULT;
		return 0;
	}
	case PCIE_BLK_IOC_GET_BS: {
		u32 v;
		mutex_lock(&d->lock);
		v = d->block_size;
		mutex_unlock(&d->lock);
		if (copy_to_user((void __user *)arg, &v, sizeof(v)))
			return -EFAULT;
		return 0;
	}
	case PCIE_BLK_IOC_GET_STORAGESZ: {
		u64 v;
		mutex_lock(&d->lock);
		v = d->storage_size;
		mutex_unlock(&d->lock);
		if (copy_to_user((void __user *)arg, &v, sizeof(v)))
			return -EFAULT;
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations pcie_blk_fops = {
	.owner          = THIS_MODULE,
	.open           = pcie_blk_open,
	.read           = pcie_blk_read,
	.write          = pcie_blk_write,
	.unlocked_ioctl = pcie_blk_ioctl,
	.llseek         = no_llseek,
};

/* ---------- PCI probe/remove ---------- */

/*
 * Replace with actual IDs of your QEMU PCIe device (see lspci -nn in guest).
 */
#define VENDOR_ID_LAB 0x1234
#define DEVICE_ID_LAB 0x11e8

static const struct pci_device_id pcie_blk_ids[] = {
	{ PCI_DEVICE(VENDOR_ID_LAB, DEVICE_ID_LAB) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pcie_blk_ids);

static int pcie_blk_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret;
	struct pcie_blk_dev *d = &g_dev;
	u32 bs;

	memset(d, 0, sizeof(*d));
	mutex_init(&d->lock);
	d->pdev = pdev;

	ret = pci_enable_device_mem(pdev);
	if (ret)
		return ret;

	ret = pci_request_regions(pdev, DRV_NAME);
	if (ret)
		goto err_disable;

	d->bar_len = pci_resource_len(pdev, BAR_INDEX);
	d->bar = pci_iomap(pdev, BAR_INDEX, 0);
	if (!d->bar) {
		ret = -ENOMEM;
		goto err_release;
	}

	d->storage_base = mmio_read64(d->bar, REG_STORAGE_BASE);
	d->storage_size = mmio_read64(d->bar, REG_STORAGE_SIZE);
	bs = readl(d->bar + REG_BLOCK_SIZE);
	d->block_size = bs;

	if (d->block_size == 0 ||
	    (d->storage_size == 0) ||
	    (d->storage_size % d->block_size) != 0) {
		dev_err(&pdev->dev, "bad params: storage_size=%llu block_size=%u\n",
			(unsigned long long)d->storage_size, d->block_size);
		ret = -EINVAL;
		goto err_iounmap;
	}

	d->lba = 0;
	d->write_max = d->block_size * 32; /* default: 32 blocks per write */

	ret = alloc_chrdev_region(&d->devt, 0, 1, DRV_NAME);
	if (ret)
		goto err_iounmap;

	cdev_init(&d->cdev, &pcie_blk_fops);
	d->cdev.owner = THIS_MODULE;

	ret = cdev_add(&d->cdev, d->devt, 1);
	if (ret)
		goto err_chrdev;

	d->class = class_create(CLASS_NAME);
	if (IS_ERR(d->class)) {
		ret = PTR_ERR(d->class);
		goto err_cdev;
	}

	d->device = device_create(d->class, &pdev->dev, d->devt, NULL, "pcie_blk0");
	if (IS_ERR(d->device)) {
		ret = PTR_ERR(d->device);
		goto err_class;
	}

	ret = sysfs_create_group(&d->device->kobj, &pcie_blk_attr_group);
	if (ret)
		goto err_dev;

	pci_set_drvdata(pdev, d);

	dev_info(&pdev->dev, "probed: BAR2 len=%pa storage=%llu bs=%u\n",
		 &d->bar_len,
		 (unsigned long long)d->storage_size,
		 d->block_size);
	return 0;

err_dev:
	device_destroy(d->class, d->devt);
err_class:
	class_destroy(d->class);
err_cdev:
	cdev_del(&d->cdev);
err_chrdev:
	unregister_chrdev_region(d->devt, 1);
err_iounmap:
	pci_iounmap(pdev, d->bar);
err_release:
	pci_release_regions(pdev);
err_disable:
	pci_disable_device(pdev);
	return ret;
}

static void pcie_blk_remove(struct pci_dev *pdev)
{
	struct pcie_blk_dev *d = pci_get_drvdata(pdev);

	sysfs_remove_group(&d->device->kobj, &pcie_blk_attr_group);
	device_destroy(d->class, d->devt);
	class_destroy(d->class);
	cdev_del(&d->cdev);
	unregister_chrdev_region(d->devt, 1);

	pci_iounmap(pdev, d->bar);
	pci_release_regions(pdev);
	pci_disable_device(pdev);

	dev_info(&pdev->dev, "removed\n");
}

static struct pci_driver pcie_blk_driver = {
	.name = DRV_NAME,
	.id_table = pcie_blk_ids,
	.probe = pcie_blk_probe,
	.remove = pcie_blk_remove,
};

module_pci_driver(pcie_blk_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lab2");
MODULE_DESCRIPTION("PCIe Lab2 Variant 8: block-aligned char device (BAR2)");
