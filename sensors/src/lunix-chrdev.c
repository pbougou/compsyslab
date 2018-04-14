#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h> // dev_t,
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	int ret;
	struct lunix_sensor_struct *sensor;
	debug("entering lunix_chrdev_state_needs_refresh\n");
	WARN_ON ( !(sensor = state->sensor));
	
	ret = (sensor->msr_data[state->type]->last_update > state->buf_timestamp);
	
	debug("leaving lunix_chrdev_state_needs_refresh with ret = %d\n", ret);
	
	return ret;
	// debug("state time = %d\n", state->buf_timestamp);
	/* The following return is bogus, just for the stub to compile */

}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	long lookup_data;
	int must_refresh;
	uint32_t new_msr;
	uint32_t new_timestamp;
	unsigned long flags;
	debug("entering lunix_chrdev_state_update\n");
	sensor = state->sensor;
	WARN_ON(!sensor);
	

	/* race condition: sensor's buffers */

	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	
	/* Why use spinlocks? See LDD3, p. 119 */

	/*
	 * spin_lock / spin_lock_irqsave / spin_lock_irq / spin_lock_bh (ldd p.119)
	 */
	spin_lock_irqsave(&sensor->lock, flags);
	if((must_refresh = lunix_chrdev_state_needs_refresh(state))) {
		new_msr = sensor->msr_data[state->type]->values[0];
		new_timestamp = sensor->msr_data[state->type]->last_update;
		debug("New_data: msr = %d, time = %d\n", new_msr, new_timestamp);

	}
	spin_unlock_irqrestore(&sensor->lock, flags);
/*
 * Format data received from lookup_tables: { lookup_temperature, lookup_voltage, lookup_light }
 * Race condition: state is one for every open file so 
 *	                race condition exists when processes which share one fd are trying to read buf_data
 *					
 */
	/*
	 * Any new data available?
	 */

	if(must_refresh) {
	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */
		if(state->mode) {
          switch(state->type) {
              // Battery: lookup_voltage
              case 0:
                 lookup_data = lookup_voltage[new_msr];
                  printk(KERN_DEBUG "lookup_data = %ld", lookup_data);
                  break;
              // Temperature: lookup_temperature
              case 1:
                  lookup_data = lookup_temperature[new_msr];
                  printk(KERN_DEBUG "lookup_data = %ld", lookup_data);
                  break;
              // Light: light
              case 2:
                  lookup_data = lookup_light[new_msr];
                  printk(KERN_DEBUG "lookup_data = %ld", lookup_data);
                  break;
              // No such type of device
              default:
                  debug("The impossible happenned\n");
				  return -ENOMEDIUM;
		}

			state->buf_lim = snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ, "%c%ld.%ld\n", (lookup_data >= 0 ? '+' : '-'), lookup_data / 1000, lookup_data % 1000);	
			state->buf_data[LUNIX_CHRDEV_BUFSZ - 1] = '\0';
			debug("Format_data_cooked: %s\n", state->buf_data);
			debug("leaving lunix_chrdev_state_update with cooked refreshed data\n");
		}
		else {
			state->buf_lim = snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ, "%ld\n", new_msr);	
			state->buf_data[LUNIX_CHRDEV_BUFSZ - 1] = '\0';
			debug("Format_data_raw: %s\n", state->buf_data);
			debug("leaving lunix_chrdev_state_update with raw refreshed data\n");
			
		}
		state->buf_timestamp = get_seconds();
		return 0;
	}
	else {
		debug("leaving lunix_chrdev_state_update with no refreshed data\n");
		return -EAGAIN;
	}
		return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/* ? */
	int ret;
	unsigned int sensor;
	struct lunix_chrdev_state_struct *state;
	debug("entering lunix_chrdev_open\n");

	// No such device error
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */


	
	/* Allocate a new Lunix character device private state structure */
	state = (struct lunix_chrdev_state_struct *)kmalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL);

	if(state == NULL) {
		printk(KERN_ERR "Failed to allocate memory.\n");
	}

	if((ret = iminor(inode)) < 0)
		goto out;

	sensor = ret >> 3;

	state->type = ret % 8;
	state->buf_lim = LUNIX_CHRDEV_BUFSZ;
	state->sensor = &lunix_sensors[sensor];
	state->mode = 1; /* 1: cooked, 0:raw  */
	sema_init(&state->lock, 1);
	// spin_lock_init(&state->lock);
	debug("sensor_type is %d and minor = %d\n", state->type, iminor(inode));
	filp -> private_data = state;

	return 0;

	/* ? */
out:
	debug("leaving lunix_chrdev_open, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	/* ? */
	debug("entering lunix_chrdev_release\n");
	kfree(filp->private_data);
	debug("Lunix:TNG: leaving lunix_chrdev_release... Deallocation was successful\n");
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct lunix_chrdev_state_struct *state; 
	state = filp->private_data;
	if(cmd == LUNIX_IO_SET_MODE) {	
		state->mode = !state->mode;
		printk(KERN_INFO "In the ioctl command\n");
		return 0;
	}
	else {
		printk(KERN_INFO "Bad command\n");
		return -ENOTTY;

	}

	/* ioctl is not supported */
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos) {
	unsigned long flags;
	ssize_t ret;
	int nr_bytes_available;
	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	/* Why? */
	state = filp->private_data;
	WARN_ON(!state);

	/* Why? */
	sensor = state->sensor;
	WARN_ON(!sensor);
	debug("lunix_chrdev_read: cnt = %d and ", (int)cnt);
	debug("<f_pos> = %d\n", (int)*f_pos);
	/* Lock? */
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if(down_interruptible(&state->lock))
	 	return -ERESTARTSYS;
	// spin_lock_irqsave(&state->lock, flags);
	
	if (*f_pos == 0) {
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			/* ? */
			/* The process needs to sleep */
			/* See LDD3, page 153 for a hint */
			up(&state->lock);

			// spin_unlock_irqrestore(&state->lock, flags);
			if(wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state)))
				return -ERESTARTSYS;

			//spin_lock_irqsave(&state->lock, flags);
			if(down_interruptible(&state->lock))
				return -ERESTARTSYS;
		}
	}
	debug("lunix_chrdev_read: new_msr shown up... f_pos = %d\n", (int)*f_pos);

	/* 
	 * User process asks for cnt bytes
	 * buf_data has buf_lim bytes
	 */

	/* Determine the number of cached bytes to copy to userspace */
	nr_bytes_available = state->buf_lim - (int)*f_pos;
	if(cnt >= nr_bytes_available)
		ret = nr_bytes_available;
	else
		ret = cnt;

	if(copy_to_user(usrbuf, &((state->buf_data)[*f_pos]), ret)) {
		// spin_unlock_irqrestore(&state->lock, flags);
		up(&state->lock);
		return -EFAULT;
	} 
	
	/* so far so good: f_pos update remains */
	*f_pos = *f_pos + ret;

	/* Auto-rewind on EOF mode? */
	/* End of file */
	if(*f_pos == state->buf_lim) {
		debug("lunix_chrdev_read: Reached end of file\n");
		*f_pos = 0;
	}
	// spin_unlock_irqrestore(&state->lock, flags);
	
	up(&state->lock);
	return ret;
	


/*
out:
	// Unlock?
	return ret;
*/
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
    .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	/* ? */
	/* register_chrdev_region? */
	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "Lunix:TNG");
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out_with_chrdev_region;
	}	
	/* ? */
	/* cdev_add? */
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device with ret = %d\n", ret);
		goto out_with_chrdev_region;
	}

	debug("lunix_chrdev_init completed successfully\n");
	return 0;

out_with_chrdev_region:
	debug("lunix_chrdev_init: entering out_with_chrdev_region label with ret = %d\n", ret);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("lunix_chrdev_init: entering out label with ret = %d\n", ret);
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

	debug("entering lunix_chrdev_destroy\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving lunix_chrdev_destroy\n");
}
