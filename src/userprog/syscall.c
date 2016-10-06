#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void halt(void);
bool create(const char *file, unsigned size);
bool remove(const char *file);
tid_t exec(const char *cmdline);
int wait(tid_t tid);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

struct lock filesys_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}


void check_address(void *addr)
{
	if((unsigned)addr < 0x8048000 || !is_user_vaddr(addr))
		exit(-1);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int syscall_index;
	char *esp_addr = f->esp;

	check_address(esp_addr);
	check_address(esp_addr+3);

	syscall_index = *(int*)(esp_addr);

	switch(syscall_index)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		check_address(esp_addr+4);
		exit(*(int*)(esp_addr+4));
		break;
	case SYS_CREATE:
		check_address(esp_addr+4);
		check_address(esp_addr+8);
		check_address(*(void**)(esp_addr+4));
		f->eax = create(*(const char**)(esp_addr+4),*(unsigned*)(esp_addr+8));
		break;
	case SYS_REMOVE:
		check_address(esp_addr+4);
		check_address(*(void**)(esp_addr+4));
		f->eax = remove(*(const char**)(esp_addr+4));
		break;
	case SYS_EXEC:
		check_address(esp_addr+4);
		check_address(*(void**)(esp_addr+4));
		f->eax = exec(*(const char**)(esp_addr+4));
		break;
	case SYS_WAIT:
		check_address(esp_addr+4);
		f->eax = wait(*(int*)(esp_addr+4));
		break;
	case SYS_OPEN:
		check_address(esp_addr+4);
		f->eax = open(*(const char**)(esp_addr+4));
	case SYS_CLOSE:
		check_address(esp_addr+4);
		close(*(int*)(esp_addr+4));
		break;
	case SYS_READ:
		check_address(esp_addr+4);
		check_address(esp_addr+8);
		check_address(esp_addr+12);
		check_address(*(void**)(esp_addr+8));
		f->eax = read(*(int*)(esp_addr+4),*(void **)(esp_addr+8),*(unsigned*)(esp_addr+12));
		break;
	case SYS_WRITE:
		check_address(esp_addr+4);
		check_address(esp_addr+8);
		check_address(esp_addr+12);
		check_address(*(void**)(esp_addr+8));
		f->eax = write(*(int*)(esp_addr+4),*(void **)(esp_addr+8),*(unsigned*)(esp_addr+12));
		break;
	case SYS_SEEK:
		check_address(esp_addr+4);
		check_address(esp_addr+8);
		seek(*(int*)(esp_addr+4),*(unsigned*)(esp_addr+8));
		break;
	case SYS_TELL:
		check_address(esp_addr+4);
		f->eax = tell(*(int*)(esp_addr+4));
		break;
	case SYS_FILESIZE:
		check_address(esp_addr+4);
		f->eax = filesize(*(int*)(esp_addr+4));
		break;
	default:
		thread_exit();
	}
}

void halt()
{
	shutdown_power_off();
}

void exit(int status)
{
	struct thread *curr_thread = thread_current();
	printf("%s: exit(%d)\n",thread_name(),status);
	curr_thread->exit_status = status;
	thread_exit();
}

bool create(const char *file, unsigned size)
{
	bool ret;
	
	if(file == NULL)
		exit(-1);
	
	lock_acquire(&filesys_lock);
	ret = filesys_create(file,size);
	lock_release(&filesys_lock);

	return ret;
}

bool remove(const char *file)
{
	if(file == NULL)
		exit(-1);
	return filesys_remove(file);
}

tid_t exec(const char *cmdline)
{
	tid_t new_tid;
	struct thread *child;

	new_tid = process_execute(cmdline);
	if(new_tid == -1)
		return -1;
	child = get_child_thread(new_tid);
	if(child == NULL)
		return -1;
	//wait for child until loaded
	sema_down(&child->load_sema);
	if(!child->is_loaded)
		return -1;
	
	return new_tid;
}

int wait(tid_t tid)
{
	return process_wait(tid);
}

int open(const char *file)
{
	struct file *f;
	int fd;
	
	if(file == NULL)
		return -1;
	
	lock_acquire(&filesys_lock);
	
	f = filesys_open(file);
	if(f == NULL)
		fd = -1;
	else
		fd = process_add_file(f);

	lock_release(&filesys_lock);

	return fd;
}

int filesize(int fd)
{
	struct file *f = process_get_file(fd);
	if(f == NULL)
		return -1;
	return file_length(f);
}

int read(int fd, void *buffer, unsigned size)
{
	struct file *f;
	char ch;
	int i=0;
	off_t length;

	lock_acquire(&filesys_lock);

	if(fd == 0) //STDIN
	{
		while((ch = input_getc()) != -1)
			((char*)buffer)[i++] = ch;
		length = i;
	}
	else
	{
		f = process_get_file(fd);
		if(f == NULL)
			length = -1;
		else
			length = file_read(f,buffer,size);
	}

	lock_release(&filesys_lock);

	return length;
}

int write(int fd, void *buffer, unsigned size)
{
	struct file *f;
	off_t length;

	lock_acquire(&filesys_lock);

	if(fd == 1) //STDOUT
	{
		putbuf(buffer,size);
		length = size;
	}
	else
	{
		f = process_get_file(fd);
		if(f == NULL)
			length = -1;
		else
			length = file_write(f,buffer,size);
	}

	lock_release(&filesys_lock);

	return length;
}

void seek(int fd, unsigned position)
{
	struct file *f;
	f = process_get_file(fd);
	if(f != NULL)
		file_seek(f,position);
}

unsigned tell(int fd)
{
	struct file *f;
	f = process_get_file(fd);
	if(f == NULL)
		return -1;
	return file_tell(f);
}

void close(int fd)
{
	process_close_file(fd);
}

