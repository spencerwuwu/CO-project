// See LICENSE for license details.

#include "cachesim.h"
#include "common.h"
#include <cstdlib>
#include <iostream>
#include <iomanip>

cache_sim_t::cache_sim_t(size_t _sets, size_t _ways, size_t _linesz, const char* _name)
 : sets(_sets), ways(_ways), linesz(_linesz), name(_name)
{
  init();
}

static void help()
{
  std::cerr << "Cache configurations must be of the form" << std::endl;
  std::cerr << "  sets:ways:blocksize" << std::endl;
  std::cerr << "where sets, ways, and blocksize are positive integers, with" << std::endl;
  std::cerr << "sets and blocksize both powers of two and blocksize at least 8." << std::endl;
  exit(1);
}

cache_sim_t* cache_sim_t::construct(const char* config, const char* name)
{
  const char* wp = strchr(config, ':');
  if (!wp++) help();
  const char* bp = strchr(wp, ':');
  if (!bp++) help();

  size_t sets = atoi(std::string(config, wp).c_str());
  size_t ways = atoi(std::string(wp, bp).c_str());
  size_t linesz = atoi(bp);

  if (ways > 4 /* empirical */ && sets == 1)
    return new fa_cache_sim_t(ways, linesz, name);
  return new cache_sim_t(sets, ways, linesz, name);
}

void cache_sim_t::init()
{
  if(sets == 0 || (sets & (sets-1)))
    help();
  if(linesz < 8 || (linesz & (linesz-1)))
    help();

  idx_shift = 0;
  for (size_t x = linesz; x>1; x >>= 1)
    idx_shift++;

  tags = new uint64_t[sets*ways]();
  num = new uint64_t[sets]();
  read_accesses = 0;
  read_misses = 0;
  bytes_read = 0;
  write_accesses = 0;
  write_misses = 0;
  bytes_written = 0;
  writebacks = 0;
  miss_handler = NULL;

  for (size_t i = 0; i < sets*ways; i++) {
	  tags[i] = 0;
  }
	
  // Link list init
  head = new MRU_block[sets];
  tail = new MRU_block[sets];
  for (size_t i = 0; i < sets; i++) {
	 head[i]->often_use_modify(NULL);
	 head[i]->less_use_modify(NULL);
	 tail[i] = head[i];
  	 num[i] = 0;
  }

}

cache_sim_t::cache_sim_t(const cache_sim_t& rhs)
 : sets(rhs.sets), ways(rhs.ways), linesz(rhs.linesz),
   idx_shift(rhs.idx_shift), name(rhs.name)
{
  tags = new uint64_t[sets*ways];
  memcpy(tags, rhs.tags, sets*ways*sizeof(uint64_t));
  
  // Structure of the link list
  //  __     __     __     __     __     __
  // |__|<=>|__|<=>|__|<=>|__|<=>|__|<=>|__|
  //        ^                           ^  
  //        |                           | 
  //        tail                        head
  //        ______________________             ______________________
  //       | tag_pos  |    tag    |           | tag_pos  |    tag    |
  //       |__________|___________|           |__________|___________|
  //       | less_use | often_use |---------->| less_use | often_use |
  //       |__________| __________|<----+     |__________| __________|
  //                                    +----------------------+
  //

  // Init MRU list

  for(size_t i = 1; i < sets; i++){
  	// Create first list's object
  	MRU_block* now = new MRU_block;
  	now->tag_modify(tags[i*ways]);
  	now->tag_index_modify(i*ways);
  	now->less_use_modify(NULL);
  	now->often_use_modify(NULL);
  	tail[i] = now;

  	// Finish rest of the list
  	for(size_t j = 1; j < ways; j++){
  	  MRU_block* tmp;
	  tmp = new MRU_block;
	  tmp->often_use_modify(NULL);
	  tmp->less_use_modify(now[i]);
	  tmp->tag_modify(tags[i*ways+j]);
	  tmp->tag_index_modify(i*ways+j);
	  now[i] = tmp;
    }

  	head[i] = now[i];
  }


}

cache_sim_t::~cache_sim_t()
{
  print_stats();
  delete [] tags;
}

void cache_sim_t::print_stats()
{
  if(read_accesses + write_accesses == 0)
    return;

  float mr = 100.0f*(read_misses+write_misses)/(read_accesses+write_accesses);

  std::cout << std::setprecision(3) << std::fixed;
  std::cout << name << " ";
  std::cout << "Bytes Read:            " << bytes_read << std::endl;
  std::cout << name << " ";
  std::cout << "Bytes Written:         " << bytes_written << std::endl;
  std::cout << name << " ";
  std::cout << "Read Accesses:         " << read_accesses << std::endl;
  std::cout << name << " ";
  std::cout << "Write Accesses:        " << write_accesses << std::endl;
  std::cout << name << " ";
  std::cout << "Read Misses:           " << read_misses << std::endl;
  std::cout << name << " ";
  std::cout << "Write Misses:          " << write_misses << std::endl;
  std::cout << name << " ";
  std::cout << "Writebacks:            " << writebacks << std::endl;
  std::cout << name << " ";
  std::cout << "Miss Rate:             " << mr << '%' << std::endl;
}

uint64_t* cache_sim_t::check_tag(uint64_t addr)
{
  size_t idx = (addr >> idx_shift) & (sets-1);
  size_t tag = (addr >> idx_shift) | VALID;

  for (size_t i = 0; i < ways; i++)
    if (tag == (tags[idx*ways + i] & ~DIRTY)){

		// Re-order link list
		size_t j = 0;
		for(MRU_block* ptr = head[idx]; j < num[idx]; ptr = ptr->block_less_use()){
			if(tag == ptr->tag_contain_show()){
				if(ptr != head[idx]){
					// If is head, doesn't need to  change anything
					MRU_block* tmp = ptr->block_less_use();
					tmp->often_use_modify(ptr->block_often_use());
					(ptr->block_often_use())->less_use_modify(tmp->block_less_use());
					head[idx]->often_use_modify(ptr);
					ptr->often_use_modify(NULL);
					ptr->less_use_modify(head[idx]);
					head[idx] = ptr;
				}
				break;// finish refresh
			}
			j++;

		}
		return &tags[idx*ways + i];
	}

  return NULL;
}

uint64_t cache_sim_t::victimize(uint64_t addr)
{
  uint64_t victim;
  size_t idx = (addr >> idx_shift) & (sets-1);

  if (num[idx] > (ways+1)) {
	victim = head[idx]->tag_contain_show();
	MRU_block * new_head;
	new_head = new MRU_block;
	new_head->less_use_modify(head[idx]->block_less_use());
	new_head->often_use_modify(NULL);
	new_head->tag_modify(((addr >> idx_shift) | VALID));
	new_head->tag_index_modify(head[idx]->tag_index());
	(head[idx]->block_less_use())->often_use_modify(new_head);

	MRU_block* tmp;
	tmp = head[idx];
	head[idx] = new_head;
	delete tmp;

	tags[head[idx]->tag_index()] = (addr >> idx_shift) | VALID;

  }
  else {
 	size_t way = num[idx] + 1;
  	victim = tags[idx*ways + way];

	if(num[idx] == 0){
		head[idx]->tag_modify(((addr >> idx_shift) | VALID));
		head[idx]->tag_index_modify((idx*ways + way));
		head[idx]->less_use_modify(NULL);
	}
	else {
		MRU_block* tmp;
		tmp = new MRU_block;
		head[idx]->often_use_modify(tmp);
		tmp->less_use_modify(head[idx]);
		tmp->often_use_modify(NULL);
		tmp->tag_modify(((addr >> idx_shift) | VALID));
		tmp->tag_index_modify((idx*ways + way));
		head[idx] = tmp;
	} 
  	tags[idx*ways + way] = (addr >> idx_shift) | VALID;
	num[idx]++;
  }
  return victim;
}

void cache_sim_t::access(uint64_t addr, size_t bytes, bool store)
{
  store ? write_accesses++ : read_accesses++;
  (store ? bytes_written : bytes_read) += bytes;

  uint64_t* hit_way = check_tag(addr);
  if (likely(hit_way != NULL))
  {
    if (store)
      *hit_way |= DIRTY;
    return;
  }

  store ? write_misses++ : read_misses++;

  uint64_t victim = victimize(addr);

  if ((victim & (VALID | DIRTY)) == (VALID | DIRTY))
  {
    uint64_t dirty_addr = (victim & ~(VALID | DIRTY)) << idx_shift;
    if (miss_handler)
      miss_handler->access(dirty_addr, linesz, true);
    writebacks++;
  }

  if (miss_handler)
    miss_handler->access(addr & ~(linesz-1), linesz, false);

  if (store)
    *check_tag(addr) |= DIRTY;
}

fa_cache_sim_t::fa_cache_sim_t(size_t ways, size_t linesz, const char* name)
  : cache_sim_t(1, ways, linesz, name)
{
}

uint64_t* fa_cache_sim_t::check_tag(uint64_t addr)
{
  auto it = tags.find(addr >> idx_shift);
  return it == tags.end() ? NULL : &it->second;
}

uint64_t fa_cache_sim_t::victimize(uint64_t addr)
{
  uint64_t old_tag = 0;
  if (tags.size() == ways)
  {
    auto it = tags.begin();
    std::advance(it, lfsr.next() % ways);
    old_tag = it->second;
    tags.erase(it);
  }
  tags[addr >> idx_shift] = (addr >> idx_shift) | VALID;
  return old_tag;
}
