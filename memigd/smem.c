/* shared memory buffer between kernel & user space */
#include "memigd.h"
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mm.h>

// reference: https://www.cntofu.com/book/46/linux_driver/mmap_driver_implementation.md
// https://stackoverflow.com/questions/10760479/how-to-mmap-a-linux-kernel-buffer-to-user-space

// you need this patch for debugfs mmap to work: https://patches.linaro.org/project/lkml/patch/20160729143459.2672-1-Liviu.Dudau@arm.com/
// if you don't want to patch kernel, implement a char dev or use the procfs

struct dentry *smem_filp;
static char *smem_buf_page;
#define BUFFER_SIZE 4096

struct mmap_info {
	char *data;				/* the data */
	int reference;			/* how many times it is mmapped */  	
};

int smem_mmap(struct file *filp, struct vm_area_struct *vma);
int smem_close(struct inode *inode, struct file *filp);
int smem_open(struct inode *inode, struct file *filp);

/* keep track of how many times it is mmapped */

void mmap_open(struct vm_area_struct *vma)
{
	struct mmap_info *info = (struct mmap_info *)vma->vm_private_data;
	info->reference++;
}

void mmap_close(struct vm_area_struct *vma)
{
	struct mmap_info *info = (struct mmap_info *)vma->vm_private_data;
	info->reference--;
}

vm_fault_t mmap_fault(struct vm_fault* vmf)
{
	struct page *page;
	struct mmap_info *info;
	struct vm_area_struct *vma = vmf->vma;
	unsigned long address = (unsigned long)vmf->real_address;
	LOG_CALL();
	/* is the address valid? */
	if (address > vma->vm_end) {
		pr_info("invalid address");
		return VM_FAULT_SIGBUS;
	}
	/* the data is in vma->vm_private_data */
	info = (struct mmap_info *)vma->vm_private_data;
	if (!info->data) {
		pr_info("no data");
		return VM_FAULT_SIGBUS;
	}

	/* get the page */
	page = virt_to_page(info->data);
	
	/* increment the reference count of this page */
	get_page(page);
	vmf->page = page;
	return 0;
}

struct vm_operations_struct mmap_vm_ops = {
	.open =     mmap_open,
	.close =    mmap_close,
	.fault =	mmap_fault,
};

int smem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	LOG_CALL();
	vma->vm_ops = &mmap_vm_ops;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	/* assign the file private data to the vm private data */
	vma->vm_private_data = filp->private_data;
	mmap_open(vma);
	return 0;
}

int smem_close(struct inode *inode, struct file *filp)
{
	LOG_CALL();
	struct mmap_info *info = filp->private_data;
	/* obtain new memory */
	free_page((unsigned long)info->data);
	kfree(info);
	filp->private_data = NULL;
	return 0;
}

int smem_open(struct inode *inode, struct file *filp)
{
	LOG_CALL();
	struct mmap_info *info = kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
	/* obtain new memory */
    info->data = smem_buf_page;
	/* TODO fill this page with actual content */
	memcpy(info->data, "hello from kernel this is file: ", 32);
	memcpy(info->data + 32, filp->f_path.dentry->d_iname, strlen(filp->f_path.dentry->d_iname));
	/* assign this info struct to the file */
	filp->private_data = info;
	return 0;
}

static ssize_t smem_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    struct mmap_info *info;
    ssize_t ret;
	LOG_CALL();

    if ((size_t)BUFFER_SIZE <= *off) {
        ret = 0;
    } else {
        info = filp->private_data;
        ret = min(len, (size_t)BUFFER_SIZE - (size_t)*off);
        if (copy_to_user(buf, info->data + *off, ret)) {
            ret = -EFAULT;
        } else {
            *off += ret;
        }
    }
    return ret;
}

static ssize_t smem_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
    struct mmap_info *info;
	LOG_CALL();

    info = filp->private_data;
    if (copy_from_user(info->data, buf, min(len, (size_t)BUFFER_SIZE))) {
        return -EFAULT;
    } else {
        return len;
    }
}


static const struct file_operations fops = {
    .mmap = smem_mmap,
    .open = smem_open,
    .release = smem_close,
	.read = smem_read,
	.write = smem_write,
};

void *smem_init(const char *fname, struct dentry *parent)
{
    smem_filp = debugfs_create_file(fname, 0644, parent, NULL, &fops);
	smem_buf_page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!smem_buf_page) {
		return ERR_PTR(-ENOMEM);
	}
    if (IS_ERR_OR_NULL(smem_filp)) {
		return smem_filp;
    }
    return smem_buf_page;
}

void smem_exit(void)
{
	debugfs_remove(smem_filp);
}

MODULE_LICENSE("GPL");