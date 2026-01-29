/* pciblk_uapi.h */
#pragma once
#include <linux/ioctl.h>
#include <linux/types.h>

#define PCIBLK_IOC_MAGIC  'p'

/* адрес в области хранения (байтовый), должен быть кратен block_size */
#define PCIBLK_IOC_SET_ADDR     _IOW(PCIBLK_IOC_MAGIC, 1, __u64)
#define PCIBLK_IOC_GET_ADDR     _IOR(PCIBLK_IOC_MAGIC, 2, __u64)

/* размер блока (например 1024/2048/4096) */
#define PCIBLK_IOC_SET_BLKSZ    _IOW(PCIBLK_IOC_MAGIC, 3, __u32)
#define PCIBLK_IOC_GET_BLKSZ    _IOR(PCIBLK_IOC_MAGIC, 4, __u32)

/* информация от устройства */
struct pciblk_info {
	__u64 storage_base; /* RO */
	__u64 storage_size; /* RO */
};

#define PCIBLK_IOC_GET_INFO     _IOR(PCIBLK_IOC_MAGIC, 5, struct pciblk_info)
