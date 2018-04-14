/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/spinlock.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

/* done */
static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	unsigned long flags;
	int ret = -1;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type; 
	int *host_fd;
	struct scatterlist syscall_type_sg, host_fd_sg,
	                   *sgs[2];

	debug("Entering");

	syscall_type  = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	host_fd       = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	*host_fd      = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	
	/* minor works fine */
	debug("minor = %d\n", iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}

	crof->crdev        = crdev;
	crof->host_fd      = -1;
	filp->private_data = crof;
	debug("open: allocation was successful\n");
	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/

	// 0. syscall type
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[0] = &syscall_type_sg;

	// 1. host_fd
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[1] = &host_fd_sg;

	spin_lock_irqsave(&crdev->lock, flags);
	err = virtqueue_add_sgs(crdev->vq, sgs, 1, 1, &syscall_type_sg, GFP_ATOMIC);
	
	virtqueue_kick(crdev->vq);

	/**
	 * Wait for the host to process our data.
	 **/
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;
	spin_unlock_irqrestore(&crdev->lock, flags);

	/* If host failed to open() return -ENODEV. */
	if(*host_fd < 0)	{ return -ENODEV;           }
	else { 
		crof->host_fd = *host_fd; if(*host_fd > 0) ret = 0;
		debug("HOST_FD = %d\n", *host_fd);
	}
fail:
	debug("Leaving");
	kfree(syscall_type);
	kfree(host_fd);
	return ret;
}

/* done */
static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	unsigned long flags;
	int ret = 0;
	int err;
	int *host_fd;
	unsigned int len;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev   = crof->crdev;
	unsigned int *syscall_type;
	struct scatterlist syscall_type_sg, host_fd_sg,
					   *sgs[2];

	debug("Entering");

	syscall_type  = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	host_fd       = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;
	*host_fd      = crof->host_fd;

	/**
	 * Send data to the host.
	 **/
	
	// 0. syscall type
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[0] = &syscall_type_sg;

	// 1. host_fd
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[1] = &host_fd_sg;

	spin_lock_irqsave(&crdev->lock, flags);
	err = virtqueue_add_sgs(crdev->vq, sgs, 2, 0, &syscall_type_sg, GFP_ATOMIC);

	/**
	 * Wait for the host to process our data.
	 **/
	virtqueue_kick(crdev->vq);

	while(virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;
	spin_unlock_irqrestore(&crdev->lock, flags);

	kfree(syscall_type);
	kfree(host_fd);

	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	int err, ret = 0;
	unsigned long flags;

	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev   = crof->crdev;
	struct virtqueue *vq          = crdev->vq;
	struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg,
					   host_fd_sg, ioctl_cmd_sg, session_key_sg, sess_sg,
					   host_return_val_sg, ses_id_sg,
					   crypt_op_sg, src_sg, dst_sg, iv_sg,
	                   *sgs[13];
	unsigned int num_out, num_in, len;

#define MSG_LEN 100

	unsigned char *output_msg, *input_msg;
	unsigned int *syscall_type, *ioctl_cmd;
	int *host_fd, *host_return_val;

	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	output_msg       = kmalloc(MSG_LEN, GFP_KERNEL);
	input_msg        = kmalloc(MSG_LEN, GFP_KERNEL);
	syscall_type     = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	host_fd          = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	ioctl_cmd        = kmalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	host_return_val  = kmalloc(sizeof(*host_return_val), GFP_KERNEL);
	*syscall_type    = VIRTIO_CRYPTO_SYSCALL_IOCTL;
	*host_fd         = crof->host_fd;
	*ioctl_cmd       = cmd;
	*host_return_val = 0;
	num_out          = 0;
	num_in           = 0;

	debug("IOCTL: HOST_FD = %d\n", *host_fd);
	/**
	 *  These are common to all ioctl commands.
	 **/

	// 0. syscall_type
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	// 1. host_fd
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;

	// 2. cmd
	sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
	sgs[num_out++] = &ioctl_cmd_sg;
	/* ?? */

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
		case CIOCGSESSION: {
			debug("CIOCGSESSION");
			memcpy(output_msg, "Hello HOST from ioctl CIOCGSESSION.", 36);
			input_msg[0] = '\0';
			struct session_op *sess;
			unsigned char *session_key;
			sess        = kmalloc(sizeof(*sess), GFP_KERNEL);

			if(copy_from_user(sess, (struct session_op *)arg, sizeof(struct session_op))) {
				debug("I don't have a good feeling for that\n");
				return -ENODATA;
			}
			
			session_key = kmalloc(sess->keylen, GFP_KERNEL);
			if(copy_from_user(session_key, sess->key, sess->keylen)) {
				debug("I don't have a good feeling for that\n");
				return -ENODATA;
			}

			// 3. output_msg
			sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
			sgs[num_out++] = &output_msg_sg;

			// 4. session_key
			sg_init_one(&session_key_sg, session_key, sess->keylen);
			sgs[num_out++] = &session_key_sg;

			// 0. input
			sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
			sgs[num_out + num_in++] = &input_msg_sg;
			
			// 1. session
			sg_init_one(&sess_sg, sess, sizeof(*sess));
			sgs[num_out + num_in++] = &sess_sg;

			// 2. host_return_val
			sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
			sgs[num_out + num_in++] = &host_return_val_sg;

			/**
			 * Wait for the host to process our data.
			 **/
			/* Lock: race condition at vq(one per cryptodevice) */
			spin_lock_irqsave(&crdev->lock, flags);
			err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
									&syscall_type_sg, GFP_ATOMIC);
			virtqueue_kick(vq);
			while (virtqueue_get_buf(vq, &len) == NULL)
				/* do nothing */;
			spin_unlock_irqrestore(&crdev->lock, flags);

			/* copying to userspace  */
			if(copy_to_user((struct session_op *)arg, sess, sizeof(struct session_op))) {
				debug("I don't have a good feeling for that\n");
				return -EFAULT;
			}

			kfree(session_key);
			kfree(sess);
			
			break;
		}

		case CIOCFSESSION: {
			debug("CIOCFSESSION");
			memcpy(output_msg, "Hello HOST from ioctl CIOCFSESSION.", 36);
			input_msg[0] = '\0';

			u32 *ses_id;
			ses_id = kmalloc(sizeof(*ses_id), GFP_KERNEL);

			if(copy_from_user(ses_id, (u32 *)arg, sizeof(u32))) {
				debug("I don't have a good feeling for that\n");
				return -ENODATA;
			}

			// 3. output
			sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
			sgs[num_out++] = &output_msg_sg;

			// 4. ses_id
			sg_init_one(&ses_id_sg, ses_id, sizeof(*ses_id));
			sgs[num_out++] = &ses_id_sg;
			
			// 0. input
			sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
			sgs[num_out + num_in++] = &input_msg_sg;

			// 1. host_ret_val
			sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
			sgs[num_out + num_in++] = &host_return_val_sg;
			
			/**
			 * Wait for the host to process our data.
			 **/

			/* Lock: race condition at vq(one per cryptodevice) */
			spin_lock_irqsave(&crdev->lock, flags);
			err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
									&syscall_type_sg, GFP_ATOMIC);
			virtqueue_kick(vq);
			while (virtqueue_get_buf(vq, &len) == NULL)
				/* do nothing */;
			spin_unlock_irqrestore(&crdev->lock, flags);

			kfree(ses_id);
			
			break;
		}
		case CIOCCRYPT: {
			debug("CIOCCRYPT");
			memcpy(output_msg, "Hello HOST from ioctl CIOCCRYPT.", 33);
			input_msg[0] = '\0';
			struct crypt_op *crypt_op;
			unsigned char *src, *iv, *dst;

			crypt_op = kmalloc(sizeof(*crypt_op), GFP_KERNEL);
			
			if(copy_from_user(crypt_op, (struct crypt_op *)arg, sizeof(struct crypt_op))) {
				debug("crypt_op: I don't have a good feeling for that\n");
				return -ENODATA;
			}

			src = kmalloc(crypt_op->len, GFP_KERNEL);
			dst = kmalloc(crypt_op->len, GFP_KERNEL);
			iv  = kmalloc(crypt_op->len, GFP_KERNEL);

			if(copy_from_user(src, crypt_op->src, crypt_op->len)) {
				debug("src: I don't have a good feeling for that\n");
				return -ENODATA;
			}
			unsigned char *copy_to_user_dst = crypt_op->dst;
			/*
			if(copy_from_user(dst, crypt_op->dst, crypt_op->len)) {
				debug("dst: I don't have a good feeling for that\n");
				return -ENODATA;
			}
			*/
			
#define IV_SIZE 16
			if(copy_from_user(iv, crypt_op->iv, IV_SIZE)) {
				debug("iv: I don't have a good feeling for that\n");
				return -ENODATA;
			}
			
			// 3. output
			sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
			sgs[num_out++] = &output_msg_sg;

			// 4. crypt_op
			sg_init_one(&crypt_op_sg, crypt_op, sizeof(*crypt_op));
			sgs[num_out++] = &crypt_op_sg;
			
			// 5. src
			sg_init_one(&src_sg, src, crypt_op->len);
			sgs[num_out++] = &src_sg;

			// 6. iv
			sg_init_one(&iv_sg, iv, crypt_op->len);
			sgs[num_out++] = &iv_sg;


			// 0. input_msg
			sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
			sgs[num_out + num_in++] = &input_msg_sg;


			// 1. dst
			sg_init_one(&dst_sg, dst, crypt_op->len);
			sgs[num_out + num_in++] = &dst_sg;

			// 2. host_return_val
			sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
			sgs[num_out + num_in++] = &host_return_val_sg;

			/*
			switch(cmd) {
				case CIOCGSESSION:
					debug("CIOCGSESSION: Before: src = %s\n", src);
					debug("CIOCGSESSION: Before: dst = %s\n", src);
				case CIOCFSESSION:
					debug("CIOCFSESSION: Before: src = %s\n", src);
					debug("CIOCFSESSION: Before: dst = %s\n", src);
				case CIOCCRYPT:
					debug("CIOCCRYPT: Before: src = %s\n", src);
					debug("CIOCCRYPT: Before: dst = %s\n", src);
			}
			*/

			/**
			 * Wait for the host to process our data.
			 **/
		
			/* Lock: race condition at vq(one per cryptodevice) */
			spin_lock_irqsave(&crdev->lock, flags);
			err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
									&syscall_type_sg, GFP_ATOMIC);
			virtqueue_kick(vq);
			while (virtqueue_get_buf(vq, &len) == NULL)
				/* do nothing */;
			spin_unlock_irqrestore(&crdev->lock, flags);
			/*
			switch(cmd) {
				case CIOCGSESSION:
					debug("CIOCGSESSION: After: src = %s\n", src);
					debug("CIOCGSESSION: After: dst = %s\n", src);
				case CIOCFSESSION:
					debug("CIOCFSESSION: After: src = %s\n", src);
					debug("CIOCFSESSION: After: dst = %s\n", src);
				case CIOCCRYPT:
					debug("CIOCCRYPT: After: src = %s\n", src);
					debug("CIOCCRYPT: After: dst = %s\n", src);
			}
			*/

			ret = *host_return_val;
			if(ret == 0) {
				// copying to userspace  
				if(copy_to_user(copy_to_user_dst, dst, crypt_op->len)) {
					debug("copy_to_user: I don't have a good feeling for that\n");
					return -EFAULT;
				}
			}

			break;
		}
		default: {
			debug("Unsupported ioctl command");
			*host_return_val = -1;
			break;
		}
	}

	debug("We said: '%s'", output_msg);
	debug("Host answered: '%s'", input_msg);

	kfree(output_msg);
	kfree(input_msg);
	kfree(syscall_type);

	ret = *host_return_val;
	kfree(host_return_val);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
