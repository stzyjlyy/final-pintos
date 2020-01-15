#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

extern struct list all_list;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *file_name_copy;
  char *new_file_name;
  tid_t tid;
 
  /*复制文件名，否则调用者和load()会发生竞争*/
  file_name_copy = palloc_get_page(0);
  if(file_name_copy==NULL)
	  return TID_ERROR;
  strlcpy(file_name_copy,file_name,PGSIZE);

  char *place_holder_ptr;

 /*分配空间并复制FILE_NAME*/
  new_file_name = malloc(strlen(file_name) + 1);
  strlcpy (new_file_name, file_name, strlen(file_name) + 1);
  new_file_name = strtok_r (new_file_name, " ", &place_holder_ptr);

  /*创建一个新线程来执行FILE_NAME*/
  tid = thread_create (new_file_name, PRI_DEFAULT, start_process, file_name_copy);

  free(new_file_name);

  if (tid == TID_ERROR)
	  palloc_free_page (file_name_copy);

  /*尝试解锁当前线程上的CHILD_LOCK*/
  sema_down(&thread_current()->child_lock);

  /*如果失败，返回错误*/
  if(!thread_current()->success)
	  return -1;
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);     //load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
  {
	  //在父节点上锁定CHILD_LOCK，然后退出
	  thread_current()->parent->success = false;
	  sema_up(&thread_current()->parent->child_lock);
	  thread_exit();
  }
  else
  {
	  //否则，在父进程上锁定CHILD_LOCK并继续
	  thread_current()->parent->success = true;
	  sema_up(&thread_current()->parent->child_lock);
  }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
	struct list_elem *element;

	struct child *child_thread = NULL;
	struct list_elem *element_1 = NULL;

	//对于列表中的每个元素
	for (element = list_begin (&thread_current()->child_proc); element != list_end (&thread_current()->child_proc); element = list_next (element))
	{
		//创建一个临时子对象，如果它是TID ==子对象的TID，则将它作为第一个元素
		struct child *temp_child = list_entry (element, struct child, elem);
		if(temp_child->tid == child_tid)
		{
			child_thread = temp_child;
			element_1 = element;
		}
	}
	//如果两者都不成功返回错误
	if(!child_thread || !element_1)
		return -1;

	thread_current()->wait_on_thread = child_thread->tid;

	//如果孩子还没有被使用，那么就锁定CHILD_LOCK
	if(!child_thread->used)
		sema_down(&thread_current()->child_lock);
	//从列表中删除TEMP元素
	int temp = child_thread->exit_error;
	list_remove(element_1);

	return temp;
}

/* Free the current process's resources. */
void
process_exit (void)
{
	struct thread *current = thread_current();
	uint32_t *pd;

	//如果当前线程的错误为-100，则退出该进程
	if(current->exit_error == -100)
		exit_process(-1);

	//打印退出代码错误
	int exit_code = current->exit_error;
	printf("%s: exit(%d)\n",current->name,exit_code);

	//获取锁，关闭所有文件，然后释放
	acquire_filesys_lock();
	file_close(thread_current()->self);
	close_files(&thread_current()->files);
	release_filesys_lock();

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = current->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      current->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  // sema_up (&temporary);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

//static bool setup_stack (void **esp);
static bool setup_stack (void **esp, char * cmdline);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  acquire_filesys_lock();
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */

  //分配空间并创建FILE_NAME的副本
  char *file_name_copy = malloc (strlen(file_name)+1);
  strlcpy(file_name_copy, file_name, strlen(file_name)+1);

  char *place_holder_ptr;
  file_name_copy = strtok_r(file_name_copy," ",&place_holder_ptr);
  
  //打开文件
  file = filesys_open (file_name_copy);

  /*释放分配给FILE_NAME副本的空间*/
  free(file_name_copy);

  if(file==NULL)
  {
	  printf ("load: %s: open failed\n", file_name);
	  goto done;
  }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp,file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
    success = true;
    file_deny_write(file);

    thread_current()->self = file;

 done:
  /* We arrive here whether the load is successful or not. */
    release_filesys_lock();
    return success;
}

/* load() helper.*/

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp,char *file_name)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
	      *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  char *symbol, *place_holder_ptr;
  int argc = 0, i;

  /*将文件名复制到已分配的CHAR **/
  char *copy = malloc(strlen(file_name) + 1);
  strlcpy (copy, file_name, strlen(file_name) + 1);

  //解析字符串并为每个令牌添加一个参数计数
  for (symbol = strtok_r (copy, " ", &place_holder_ptr); symbol != NULL; symbol = strtok_r (NULL, " ", &place_holder_ptr))
	  argc++;

  int *argv = calloc(argc,sizeof(int));

  /*解析字符串和每个标记*/
  for (symbol = strtok_r (file_name, " ", &place_holder_ptr), i = 0; symbol != NULL; symbol = strtok_r (NULL, " ", &place_holder_ptr), i++)
  {
	  /*将堆栈指针的位置向后移动令牌长度+ 1*/
	  *esp -= strlen(symbol) + 1;

	  /*使用令牌的长度+ 1作为大小，将字符串令牌复制到堆栈指针点*/
	  memcpy(*esp, symbol, strlen(symbol) + 1);

	  argv[i] = *esp;
  }

  /*而堆栈指针指向不能被16整除的位置*/
  while(((int)*esp - 4 * (argc + 3))%16 != 0)
  {
	  /*通过将0复制给每个程序，将0传递给它*/
	  /*堆栈指针指向的位置*/
	  *esp -= sizeof(char);
	  char x = 0;
	  memcpy(*esp, &x, sizeof(char));
  }

  int numero_cero = 0;
  /*通过将0复制到堆栈指针指向的位置，将0传递给程序*/
  *esp -= sizeof(int);
  memcpy(*esp, &numero_cero, sizeof(int));

  /*而参数COUNT大于-1*/
  for(i = argc - 1; i > -1; i--)
  {
	  //通过将参数复制到堆栈指针指向的位置，将参数传递给程序
	  *esp -= sizeof(int);
	  memcpy(*esp, &argv[i], sizeof(int));
  }

  /*通过将当前位置复制到堆栈指针指向的位置，将当前位置传递给程序*/
  int pt = *esp;
  *esp -= sizeof(int);
  memcpy(*esp, &pt, sizeof(int));

  /*通过将参数COUNT复制到堆栈指针指向的位置，将它传递给程序*/
  *esp -= sizeof(int);
  memcpy(*esp, &argc, sizeof(int));

  /*通过将0复制到堆栈指针指向的位置，将0传递给程序*/
  *esp -= sizeof(int);
  memcpy(*esp, &numero_cero, sizeof(int));

  /*释放参数向量和文件名的副本*/
  free(copy);
  free(argv);
 
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}