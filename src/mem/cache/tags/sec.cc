/*
 * Copyright (c) 2012-2013 ARM Limited
 * All rights reserved.
 *
 * The license below extends only to copyright in the software and shall
 * not be construed as granting a license to any other intellectual
 * property including but not limited to intellectual property relating
 * to a hardware implementation of the functionality of the software
 * licensed hereunder.  You may use the software subject to the license
 * terms below provided that you ensure that this notice is replicated
 * unmodified and in its entirety in all distributions of the software,
 * modified or unmodified, in source code or in binary form.
 *
 * Copyright (c) 2003-2005,2014 The Regents of The University of Michigan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Erik Hallnor
 */

/**
 * @file
 * Definitions of a SEC tag store.
 */

#include "mem/cache/tags/sec.hh"

#include "debug/CacheRepl.hh"
#include "mem/cache/base.hh"

SEC::SEC(const Params *p)
    : BaseSetAssoc(p)
{
	std::cout<<" L3 sector size (sec)" << secSize<<std::endl;
}

CacheBlk*
SEC::accessBlock(Addr addr, bool is_secure, Cycles &lat)
{
    CacheBlk *blk = BaseSetAssoc::accessBlock(addr, is_secure, lat);

    if (blk != nullptr) {
        // move this block to head of the MRU list
        sets[blk->set].moveToHead(blk);
        DPRINTF(CacheRepl, "set %x: moving blk %x (%s) to MRU\n",
                blk->set, regenerateBlkAddr(blk->tag, blk->set),
                is_secure ? "s" : "ns");
    }	
    return blk;
}

CacheBlk*
SEC::findVictim(Addr addr)
{
    int set = extractSet(addr);
    // grab a replacement candidate
    BlkType *blk = nullptr;
    for (int i = assoc - 1; i >= 0; i--) {
        BlkType *b = sets[set].blks[i];
        if (b->way < allocAssoc) {
            blk = b;
            break;
        }
    }
    assert(!blk || blk->way < allocAssoc);

    if (blk && blk->isValid()) {
        DPRINTF(CacheRepl, "set %x: selecting blk %x for replacement\n",
                set, regenerateBlkAddr(blk->tag, set));
    }

    return blk;
}
void 
SEC::copyData(PacketPtr pkt, CacheBlk *blk)
{
	 Addr addr = pkt->getAddr();
	 Addr tag = extractTag(addr);
	 while( blk != nullptr && blk->tag != tag)
		blk = blk->next;
	 assert(blk->tag == tag);
	 std::memcpy(blk->data, pkt->getConstPtr<uint8_t>(), blkSize);	
}
	 
void
SEC::insertBlock(PacketPtr pkt, BlkType *blk)
{
	 Addr addr = pkt->getAddr();
	 MasterID master_id = pkt->req->masterId();
	 uint32_t task_id = pkt->req->taskId();

	 if (!blk->isTouched) {
		 tagsInUse++;
		 blk->isTouched = true;
		 if (!warmedUp && tagsInUse.value() >= warmupBound) {
			 warmedUp = true;
			 warmupCycle = curTick();
		 }
	 }
	 // If we're replacing a block that was previously valid update
	 // stats for it. This can't be done in findBlock() because a
	 // found block might not actually be replaced there if the
	 // coherence protocol says it can't be.
	 
	 // check if we can compress the new block into this valid block
	 if (blk->isValid()) {
		 //intialize the dictionary for solo block
		CacheBlk *cblk = nullptr;
		int set = extractSet(addr);
		Addr tag = extractTag(addr);
		// prefer to evict an invalid block
		for (int i = 0; i < allocAssoc; ++i) {
			cblk = sets[set].blks[i];
			// find the blk from the same sector and attempt to compress it
			if ( cblk->isValid() && (cblk->tag xor tag ) < secSize ){		
				if(cblk->dictionary.size() == 0 || cblk->dictionary2.size() == 0){ 
					assert(cblk->next == nullptr);
					BaseSetAssoc::extractDict(cblk->data, cblk->dictionary, 64, entrySize, 0);
					BaseSetAssoc::extractDict(cblk->data, cblk->dictionary2, 64, entrySize, 4);
				}
			
				bool ifCompress = checkcompressbility(cblk, pkt, entrySize);
				if(ifCompress){ // add the compressde blk by Qi
					
					BaseSetAssoc::extractDict(pkt->getConstPtr<uint8_t>(), cblk->dictionary, 64, entrySize, 0);
					BaseSetAssoc::extractDict(pkt->getConstPtr<uint8_t>(), cblk->dictionary2, 64, entrySize, 4);
					cblk->compactSize ++;
					DPRINTF(Cache, "compression happens: %s %d\n", pkt->print(),
					cblk->compactSize);
					while(cblk->next != nullptr)
					cblk = cblk->next;
					uint8_t * dBlk = new uint8_t[blkSize];
					cblk->next = new CacheBlk(dBlk);						
					cblk = cblk->next;
					cblk->tag = tag;
					cblk->srcMasterId = master_id;
					cblk->task_id = task_id;
					cblk->tickInserted = curTick();
					cblk->isTouched = true;
					return;
				}
			}				
		 }
			 
		 replacements[0]++;
		 totalRefs += blk->refCount;
		 ++sampledRefs;
		 blk->refCount = 0;

		 // deal with evicted block
		 assert(blk->srcMasterId < cache->system->maxMasters());
		 occupancies[blk->srcMasterId]--;
		 blk->invalidate();			 
	 }

	 blk->isTouched = true;

	 // Set tag for new block.  Caller is responsible for setting status.
	 blk->tag = extractTag(addr);

	 // deal with what we are bringing in
	 assert(master_id < cache->system->maxMasters());
	 occupancies[master_id]++;
	 blk->srcMasterId = master_id;
	 blk->task_id = task_id;
	 blk->tickInserted = curTick();

	 // We only need to write into one tag and one data block.
	 tagAccesses += 1;
	 dataAccesses += 1;

	int set = extractSet(pkt->getAddr());
	sets[set].moveToHead(blk);
}

void
SEC::invalidate(CacheBlk *blk)
{
    BaseSetAssoc::invalidate(blk);

    // should be evicted before valid blocks
    int set = blk->set;
    sets[set].moveToTail(blk);
}

SEC*
SECParams::create()
{
    return new SEC(this);
}
