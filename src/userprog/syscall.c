#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "list.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);
void* check_ptr(const void*);
struct process_file* list_search(struct list* files, int fd);

extern bool running;
static int get_user (const uint8_t *uaddr);

/*帮助处理文件的结构*/
struct process_file
{
	struct file* ptr;
	int fd;
	struct list_elem elem;
};

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
	uint32_t *user_ptr = f->esp;

  check_ptr(user_ptr);

  uint32_t system_call = *user_ptr;

  switch (system_call)
  {
	  case SYS_HALT:
		  /*关闭系统*/
		  shutdown_power_off();
		  break;

	  case SYS_EXIT:
		  /*退出系统*/
		  check_ptr(user_ptr + 1);
		  exit_process(*(user_ptr + 1));
		  break;
	  case SYS_EXEC:
		  /*执行进程*/
		  check_ptr(user_ptr + 1);
		  check_ptr(*(user_ptr + 1));

		  f->eax = check_execute_process(*(user_ptr + 1));
		  break;

	  case SYS_WAIT:
		  /*让系统等待*/
		  check_ptr(user_ptr + 1);

		  f->eax = process_wait(*(user_ptr + 1));
		  break;

	  case SYS_PRACTICE:
		  f->eax=practice_file(*(user_ptr+1));
		  break;

	  case SYS_CREATE:
		  /*创建文件*/
		  check_ptr(user_ptr + 5);
		  check_ptr(*(user_ptr + 4));

		  /*获取文件的锁*/
		  acquire_filesys_lock();
		  f->eax = filesys_create(*(user_ptr + 4), *(user_ptr + 5));
		  /*释放文件上的锁*/
		  release_filesys_lock();
		  break;
	  case SYS_REMOVE:
		  /*获取锁后删除文件，删除文件后释放锁*/
		  check_ptr(user_ptr + 1);
		  check_ptr(*(user_ptr + 1));

		  /*获取文件的锁*/
		  acquire_filesys_lock();

		  /*如果文件为空，则使框架PTR为假，否则为真*/
		  if(filesys_remove(*(user_ptr + 1)) == NULL)
			  f->eax = false;
		  else
			  f->eax = true;

		  /*释放文件上的锁*/
		  release_filesys_lock();
		  break;

	  case SYS_OPEN:
		  /*打开文件*/
		  check_ptr(user_ptr + 1);
		  check_ptr(*(user_ptr + 1));

		  /*获取文件的锁*/
		  acquire_filesys_lock();
		  struct file *frame_ptr = filesys_open (*(user_ptr + 1));

		  /*释放文件上的锁*/
		  release_filesys_lock();

		  /*如果FRAME_PTR为NULL返回错误，则文件为用户地址空间打开*/
		  if(frame_ptr == NULL)
			  f->eax = -1;
		  else
		  {
			  struct process_file *user_ptr_file = malloc(sizeof(*user_ptr_file));

			  user_ptr_file->ptr = frame_ptr;
			  user_ptr_file->fd = thread_current()->file_count;
			  thread_current()->file_count++;
			  list_push_back (&thread_current()->files, &user_ptr_file->elem);
			  f->eax = user_ptr_file->fd;
		  }
		  break;
	  case SYS_FILESIZE:
		  /*返回文件的大小*/
		  check_ptr(user_ptr + 1);

		  acquire_filesys_lock();
		  f->eax = file_length (list_search(&thread_current()->files, *(user_ptr + 1))->ptr);
		  release_filesys_lock();
		  break;

	  case SYS_READ:
		  /*读文件*/
		  check_ptr(user_ptr + 7);
		  check_ptr(*(user_ptr + 6));

		  /*如果(USER_PTR + 5)为0，则从键盘输入*/
		  if(*(user_ptr + 5) == 0)
		  {
			   int i;
			   uint8_t* buffer = *(user_ptr + 6);

			   for(i = 0 ; i < *(user_ptr + 7); i++)
				   buffer[i] = input_getc();
			   f->eax = *(user_ptr + 7);
		  }
		  else
		  {
			  /*否则文件将被读取*/
			  struct process_file* frame_ptr = list_search(&thread_current()->files, *(user_ptr + 5));

			  /*如果FRAME_PTR为空返回错误*/
			  if(frame_ptr == NULL)
				  f->eax = -1;
			  else
			  {
				  //否则读取文件
				  acquire_filesys_lock();
				  f->eax = file_read (frame_ptr->ptr, *(user_ptr + 6), *(user_ptr + 7));
				  release_filesys_lock();
			  }
		  }
		  break;

	  case SYS_WRITE:
		  /*写入文件*/
		  check_ptr(user_ptr + 7);
		  check_ptr(*(user_ptr + 6));

		  if(*(user_ptr + 5) == 1)
		  {
			  /*将缓冲区中的字符数写入CONSOL*/
			  putbuf(*(user_ptr + 6), *(user_ptr + 7));
			  f->eax = *(user_ptr + 7);
		  }
		  else
		  {
			  struct process_file* frame_ptr = list_search(&thread_current()->files, *(user_ptr + 5));
			  /*如果FRAME_PTR为空返回错误*/
			  if(frame_ptr == NULL)
				  f->eax = -1;
			  else
			  {
				  /*否则写入文件*/
				  acquire_filesys_lock();
				  f->eax = file_write (frame_ptr->ptr, *(user_ptr + 6), *(user_ptr + 7));
				  release_filesys_lock();
			  }
		  }
		  break;

	  case SYS_SEEK:
		  /*将打开文件中的PTR移动到某个位置*/
		  check_ptr(user_ptr + 5);

		  acquire_filesys_lock();
		  file_seek(list_search(&thread_current()->files, *(user_ptr + 4))->ptr, *(user_ptr + 5));
		  release_filesys_lock();
		  break;

	  case SYS_TELL:
		  /*返回文件中要读取或写入的下一个位置的位置*/
		  check_ptr(user_ptr + 1);

		  acquire_filesys_lock();
		  f->eax = file_tell(list_search(&thread_current()->files, *(user_ptr + 1))->ptr);
		  release_filesys_lock();
		  break;

	  case SYS_CLOSE:
		  /*关闭文件*/
		  check_ptr(user_ptr + 1);

		  acquire_filesys_lock();
		  close_file(&thread_current()->files,*(user_ptr + 1));
		  release_filesys_lock();
		  break;

	  default:
		  printf("Default %d\n", *user_ptr);
  }
}

int practice_file(int i)
{
	return i+1;
}

void* check_ptr(const void *vaddr)
{
	//如果是无效的用户地址返回错误
	if (!is_user_vaddr(vaddr))
	{
		exit_process(-1);
		return 0;
	}

	void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);

	/*如果PTR没有指向有效地址返回错误*/
	if (!ptr)
	{
		exit_process(-1);
		return 0;
	}
	/*检查指针的各个字节*/
	uint8_t* check_byteptr = (uint8_t *)vaddr;

	/*如果指针的任何字节在无效内存中，则返回错误*/
	for (uint8_t i = 0; i < 4; i++)
	{
		if(get_user(check_byteptr + i) == -1)
		{
			exit_process(-1);
			return 0;
		}
	}
	return ptr;
}

int check_execute_process(char *file_name)
{
	acquire_filesys_lock();
	char *file_name_copy = malloc (strlen(file_name) + 1);
	strlcpy(file_name_copy, file_name, strlen(file_name) + 1);

	char *place_holder_ptr;
	/*在CHAR *中复制文件的名称*/
	file_name_copy = strtok_r(file_name_copy, " ", &place_holder_ptr);

	struct file *f = filesys_open (file_name_copy);

	/*如果文件是空返回错误*/
	if(f == NULL)
	{
		release_filesys_lock();
		return -1;
	}
	else
	{
		/*否则关闭文件并释放锁，返回文件名*/
		file_close(f);
		release_filesys_lock();
		return process_execute(file_name);
	}
}

void close_file(struct list* files, int fd)
{
	struct list_elem *element;

	struct process_file *f;

	/*对于列表中的每个元素*/
	for (element = list_begin (files); element != list_end (files); element = list_next (element))
	{
		/*关闭文件描述符并将其从列表中删除*/
		f = list_entry (element, struct process_file, elem);
		if(f->fd == fd)
		{
			file_close(f->ptr);
			list_remove(element);
		}
	}
	free(f);
}

void close_files(struct list* files)
{
	struct list_elem *element;

	/*当文件列表不是空的*/
	while(!list_empty(files))
	{
		/*关闭文件描述符并将其从所有文件的列表中删除*/
		element = list_pop_front(files);

		struct process_file *f = list_entry (element, struct process_file, elem);
		file_close(f->ptr);
		list_remove(element);
		free(f);
	}
}
struct process_file* list_search(struct list* files, int fd)
{
	struct list_elem *element;

	/*对于列表中的每个元素*/
	for (element = list_begin (files); element != list_end (files); element = list_next (element))
	{
		/*如果文件描述符与参数匹配，则返回匹配的文件*/
		struct process_file *f = list_entry (element, struct process_file, elem);
		if(f->fd == fd)
			return f;
	}
	return NULL;
}

void exit_process(int status)
{
	struct list_elem *element;

	/*对于列表中的每个元素*/
	for (element = list_begin (&thread_current()->parent->child_proc); element != list_end (&thread_current()->parent->child_proc); element = list_next (element))
	{
		struct child *f = list_entry (element, struct child, elem);

		/*如果虚拟内存读取与THGE内核相同的数据，那么分配帧的状态*/
		if(f->tid == thread_current()->tid)
		{
			f->used = true;
			f->exit_error = status;
		}
	}

	thread_current()->exit_error = status;

	if(thread_current()->parent->wait_on_thread == thread_current()->tid)
		sema_up(&thread_current()->parent->child_lock);

	/*退出程式*/

	thread_exit();
}

/*尝试从给定的用户地址提取一个字节，如果出现页面错误，则返回错误*/
static int get_user (const uint8_t *uaddr)
{
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:": "=&a" (result) : "m" (*uaddr));
	return result;
}
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

//  if (args[0] == SYS_EXIT)
//    {
//      f->eax = args[1];
//      printf ("%s: exit(%d)\n", &thread_current ()->name, args[1]);
//      thread_exit ();
//    }
//}
