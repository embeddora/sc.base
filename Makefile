#
# Copyright (c) 2018 [n/a] info@embeddora.com All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#        * Redistributions of source code must retain the above copyright
#          notice, this list of conditions and the following disclaimer.
#        * Redistributions in binary form must reproduce the above copyright
#          notice, this list of conditions and the following disclaimer in the
#          documentation and/or other materials provided with the distribution.
#        * Neither the name of The Linux Foundation nor
#          the names of its contributors may be used to endorse or promote
#          products derived from this software without specific prior written
#          permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NON-INFRINGEMENT ARE DISCLAIMED.    IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# Prefix for 'cross'es' (purposed for future) 
PREFIX= 

CFLAGS= -g    -DEXTRA_INFORMATIVITY

#-DEXTRA_INFORMATIVITY

#-DEXTRA_PURITY

#-DEXTRA_PRECISION

OBJS= site_crawler.o

GRBG=*.o *~ site_crawler


CC=$(PREFIX)gcc

LD=$(PREFIX)ld

#.o: .s
#	$(CC) $(ASMFLAGS) -o $@ -c $< 

#.o: .c
#	$(CC) $(CFLAGS) -o $@ -c $<  

all:	site_crawler

site_crawler: $(OBJS)
	$(CC) $(CFLAGS)   $(OBJS)  -lcurl   -o $@

clean:
	rm $(GRBG) _delme.*
