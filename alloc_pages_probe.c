// Author: Alexander Schwarz
// Email: schwaa96@zedat.fu-berlin.de
// Description: Kernel probe that intercepts alloc_pages and distinguishes between planned and generic allocation
//		This was created during my master thesis
//		Note that if you compiled the kernel with alloc_tags enabled that you will get a kernel warning because this modules does not get or set any


// IMPORTS
#include <linux/kprobes.h>
#include <linux/proc_fs.h>

#define MAX_PROC 256

// STRUCTS
// NOTE: Only the field pid is used in the final implementation but I kept the other fields here anyway for future experiments 
struct planned_process 
{
	// The actual pid supplied during runtime (maps to a task_id)
	pid_t pid;

	// Plan based scheduler parameters (assumed to be correct)
	int start_time_s;
	int end_time_s;
	int memory_demand_b;

	// The identified is the task_id and pre and suc and other task_ids that come before and after it respectively (TPG data)
	int* task_pre;
	int* task_suc;

	// Other task_ids that share data with this process (TIG data) 
	int* mates;
};



// DATA STORAGE
static struct planned_process* planned_procs;
static struct page** pre_allocated_pages_orders[11];
static int amount_pages_order[11] = {32768, 16384, 8192, 4096, 2048, 1024, 512, 256, 128, 64, 32};
static int pages_order_idx[11] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// PROC FILE
static struct proc_dir_entry* proc_entry;

static ssize_t write_proc(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
	char proc_buffer[32];
	char* proc_info[6];
	char* token;
	char* rest;

	// Validity check
	if(count > (sizeof(proc_buffer)-1) )
	{return -EINVAL;}

	if(copy_from_user(proc_buffer, buffer, count))
	{return -EFAULT;}

	// Terminate string
	proc_buffer[count] = '\0';

	// Split info
	int i = 0;
	rest = proc_buffer;
	while((token = strsep(&rest, ",")) != NULL && i < 2)
	{
		proc_info[i] = token;
		i++;
	}



	// Get task_id from registering process and assign its pid to its struct
	// NOTE: Struct is identified by the task_id which serves as an index of planned_procs (i.e. planned_procs[task_id])
	int result;
	int task_id;
	result += kstrtoint(proc_info[0], 10, &task_id);
	if(result)
	{
		printk(KERN_ERR "Failed to register planned process (num_proc/result): %d\n", result);
		return count;
	}

	if(task_id >= 0 && task_id < MAX_PROC)
	{
		// Register process
		result += kstrtoint(proc_info[1], 10, &planned_procs[task_id].pid);
		printk(KERN_INFO "Registered planned process: %d/%d\n", task_id, planned_procs[task_id].pid);
	}
	else if(task_id < 0)
	{
		// Unregister process
		planned_procs[-task_id].pid = -1;
		printk(KERN_INFO "Unregistered planned process: %d\n", task_id);
	}
	
	return count;
}

static struct proc_ops proc_fops = {
	.proc_write = write_proc,
};



// ALLOC KPROBE
static int ret_alloc_pages_handler(struct kretprobe_instance* ri, struct pt_regs* regs)
{
	struct page* allocated_page = (struct page*)regs_return_value(regs);
    	unsigned long order = (unsigned long)regs->si;
	pid_t pid = current->pid;


	// Check if calling process registered itself as planned process
	for(int i = 0; i < MAX_PROC; i++)
	{
		if(planned_procs[i].pid == pid)
		{
			// DBEUG
			//printk(KERN_INFO "Found planned process\n");

			printk(KERN_INFO "order=%lu\n", order);

			// Sanity check
			if(order > 10)
			{return 0;}

			// If it has a valid page, exchange it with the pre-allocated one
			if(allocated_page && pages_order_idx[order] < amount_pages_order[order])
			{
				struct page** page_array = pre_allocated_pages_orders[order];
				struct page* pre_page = page_array[pages_order_idx[order]];
				get_page(pre_page); // Increase refcount

				printk(KERN_INFO "Original allocated page=0x%lx\n", (unsigned long)allocated_page);
				regs_set_return_value(regs, (unsigned long)pre_page);
				pages_order_idx[order] += 1;
				printk(KERN_INFO "Exchanged for pre allocated page=0x%lx, at index=%d\n", (unsigned long)pre_page, pages_order_idx[order]);

				// Check if page is already free
				if(!PageBuddy(allocated_page))
				{
					//__free_pages(allocated_page, order);
					put_page(allocated_page);
					printk(KERN_INFO "Freed original page\n");
				}
				else
				{
					printk(KERN_INFO "Page is already free\n");
				}

				return 0;
			}
			else
			{
				printk(KERN_INFO "Bad page or no more pre allocated memory\n");
			}
		}
	}

	return 0;
}

static struct kretprobe alloc_kp = {
	.handler = ret_alloc_pages_handler,
    	.kp.symbol_name = "alloc_pages_noprof", // Correct alloc_pages call as alloc_pages is just a macro for alloc_pages_noprof
	.maxactive = 1,
};



// FREE KPROBE
// NOTE: The free kprobe is mainly for debugging, it currently serves no functional purpose
static int pre_free_pages_handler(struct kprobe* kp, struct pt_regs* regs)
{
	struct page* allocated_page = (struct page*)regs->di;
    	int order = (int)regs->si;
	pid_t pid = current->pid;

	// Check if calling process registered itself as planned process
	for(int i = 0; i<MAX_PROC; i++)
	{
		if(planned_procs[i].pid == pid)
		{
			printk(KERN_INFO "Intercepting __free_pages: pid=%d, page=0x%lx, order=%d\n", (int)pid, (unsigned long)allocated_page, order); break;
		}
	}
	return 0;	
}

static struct kprobe free_kp = {
	.symbol_name = "__free_pages",
	.pre_handler = pre_free_pages_handler,
};



// KMODULE
static int __init alloc_module_init(void) {

	// Allocating	
	printk(KERN_INFO "Allocating planned_procs array\n");
	planned_procs = kmalloc(MAX_PROC * sizeof(struct planned_process), GFP_USER);
	if(!planned_procs)
	{
		printk(KERN_ERR "Failed to allocate planned_procs\n");
		return 1;
	}

	// Defaulting
	printk(KERN_INFO "Defaulting planed_procs\n");
	for(int i = 0; i < MAX_PROC; i++)
	{
		planned_procs[i].pid = -1;

		planned_procs[i].start_time_s = 0;
		planned_procs[i].end_time_s = 0;	
		planned_procs[i].memory_demand_b = 0;

		planned_procs[i].task_pre = NULL;
		planned_procs[i].task_suc = NULL;
		planned_procs[i].mates = NULL;
	}

	// Init values
   	int ret = 0;
	struct sysinfo si;
	si_meminfo(&si);

	// DEBUG
	printk(KERN_INFO "Free pages before allocation: %lu\n", si.freeram);

	// Pre-allocate pages
	for(int order = 10; order >= 0; order--)
	{
		pre_allocated_pages_orders[order] = (struct page**)kmalloc(amount_pages_order[order] * sizeof(struct page*), GFP_KERNEL);
		if(!pre_allocated_pages_orders[order])
		{
			printk(KERN_ERR "Not enough memory for allocation, didn't clear, restart required!\n");
			ret = -ENOMEM;
			return ret;
		}

		for(int i = 0; i<amount_pages_order[order]; i++)
		{
			pre_allocated_pages_orders[order][i] = alloc_pages_noprof(GFP_KERNEL, order);
			// DEBUG
			//printk(KERN_INFO "Pre allocated a page=%lx\n", (unsigned long)pre_allocated_pages_orders[order][i]); // If you wanna waste time ...
			printk(KERN_INFO "Pre allocated a pfn=%lu, order=%u\n", page_to_pfn(pre_allocated_pages_orders[order][i]), order);
		}
	}

	// DEBUG
	si_meminfo(&si);
	printk(KERN_INFO "Free pages after allocation: %lu\n", si.freeram);



	// Create planned_processes directory
	proc_entry = proc_create("planned_processes", 0666, NULL, &proc_fops);
	if(!proc_entry)
	{
		ret = -ENOMEM;
		printk(KERN_INFO "Not enough memory for planned_processes: %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "Created /proc/planned_processes\n");



    	// Register kprobes
    	ret = register_kretprobe(&alloc_kp);
    	if (ret < 0)
	{
		printk(KERN_ERR "Failed to register alloc kprobe: %d\n", ret);
		return ret;
	}
    	printk(KERN_INFO "Registered alloc_pages_noprof probe\n");
	
	ret = register_kprobe(&free_kp);
    	if (ret < 0)
	{
		printk(KERN_ERR "Failed to register free kprobe: %d\n", ret);
		return ret;
	}
    	printk(KERN_INFO "Registered __free_pages probe\n");
	
	return ret;
}

static void __exit alloc_module_exit(void) {

	// Unregister probes
    	unregister_kretprobe(&alloc_kp);
    	printk(KERN_INFO "Unregistered alloc_pages_noprof probe\n");
	
    	unregister_kprobe(&free_kp);
    	printk(KERN_INFO "Unregistered __free_pages probe\n");

	for(int order = 0; order < 11; order++)
	{
		for(int i = 0; i<amount_pages_order[order]; i++)
		{
			if(PageBuddy(pre_allocated_pages_orders[order][i]))
			{continue;}
			__free_pages(pre_allocated_pages_orders[order][i], order);
		}
	}
    	printk(KERN_INFO "Freed pages\n");

	proc_remove(proc_entry);
    	printk(KERN_INFO "Deleted /proc/planned_processes\n");

	// Free arrays
	kfree(planned_procs);
	for(int order = 0; order < 11; order++)
	{kfree(pre_allocated_pages_orders[order]);}
    	printk(KERN_INFO "Freed planned arrays\n");

    	printk(KERN_INFO "Module unloaded\n");
}



// MAIN
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Schwarz");
MODULE_DESCRIPTION("Kernel module to swap out allocated pages for plan-based processes.");

module_init(alloc_module_init);
module_exit(alloc_module_exit);

