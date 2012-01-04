include(manual.h)dnl
HEADER(sand_align_master)

SECTION(NAME)
BOLD(sand_align_master) - align candidate sequences in parallel

SECTION(SYNOPSIS)
CODE(BOLD(sand_align_master [options] sand_align_kernel candidates.cand sequences.cfa overlaps.ovl))

SECTION(DESCRIPTION)

BOLD(sand_align_master) is the second step in the SAND assembler.
It reads in a list of sequences and a list of candidate pairs
to consider, generated by MANPAGE(sand_filter_master,1).
It then performs all of the comparisons and produces a list
of overlaps (in OVL format) that exceed a quality threshhold.
PARA
This program uses the Work Queue system to distributed tasks
among processors.  After starting BOLD(sand_align_master),
you must start a number of MANPAGE(work_queue_worker,1) processes
on remote machines.  The workers will then connect back to the
master process and begin executing tasks.  The actual alignments
are performed by MANPAGE(sand_align_kernel,1) on each machine.

SECTION(OPTIONS)

OPTIONS_BEGIN
OPTION_PAIR(-p,port)Port number for work queue master to listen on. (default: 9123)
OPTION_PAIR(-n,number)Maximum number of candidates per task. (default is 10000)
OPTION_PAIR(-e,args)Extra arguments to pass to the alignment program.
OPTION_PAIR(-d,subsystem)Enable debugging for this subsystem. (Try BOLD(-d all) to start.)
OPTION_PAIR(-F,mult)Work Queue fast abort multiplier.(default is 10.)
OPTION_PAIR(-o,file)Send debugging to this file.
OPTION_ITEM(-v)Show version string.
OPTION_ITEM(-h)Show help text.
OPTIONS_END

SECTION(EXIT STATUS)
On success, returns zero.  On failure, returns non-zero.

SECTION(EXAMPLES)

Suppose that you begin with a compressed FASTA file (CODE(mydata.cfa))
and a list of candidate reads (CODE(mydata.cand)) generated by MANPAGE(sand_filter_master,1).
First, start a single MANPAGE(work_queue_worker,1) process in the background.
Then, invoke MANPAGE(sand_align_master) as follows:

LONGCODE_BEGIN
% work_queue_worker localhost 9123 &
% sand_align_master sand_align_kernel mydata.cand mydata.cfa mydata.ovl
LONGCODE_END

To speed up the process, run more MANPAGE(work_queue_worker) processes
on other machines, or use MANPAGE(condor_submit_workers,1) or MANPAGE(sge_submit_workers,1) to start hundreds of workers in your local batch system.

SECTION(COPYRIGHT)

COPYRIGHT_BOILERPLATE

SECTION(SEE ALSO)

SEE_ALSO_SAND

FOOTER

