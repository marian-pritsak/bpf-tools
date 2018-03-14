bin_PROGRAMS = bpf-sample \
	       bpf-sample-kern

bpf_sample_SOURCES = sample-user.c
bpf_sample_kern_SOURCES = sample-kern.c

bpf_sample_CFLAGS = $(CFLAGS_COMMON) \
		    -I$(IPROUTE2_SRC)

bpf_sample_kern_CFLAGS = $(CFLAGS_COMMON) \
			 $(CFLAGS_KERN) \
			 -I$(top_srcdir)/include

# A hack to disable linker, ls at the end is for prepended @<
bpf_sample_kern_LINK = cp $< $@ ; ls
