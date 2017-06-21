// See LICENSE for license details.

#include "cachesim.h"
#include "common.h"
#include <cstdlib>
#include <iostream>
#include <iomanip>
using namespace std;

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

/* Do not modify this function */
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
	//New structure
	num = 0;
	head = new LRU_block;
	end = head;
	//End of new structure
  read_accesses = 0;
  read_misses = 0;
  bytes_read = 0;
  write_accesses = 0;
  write_misses = 0;
  bytes_written = 0;
  writebacks = 0;

  miss_handler = NULL;
}

cache_sim_t::cache_sim_t(const cache_sim_t& rhs)
 : sets(rhs.sets), ways(rhs.ways), linesz(rhs.linesz),
   idx_shift(rhs.idx_shift), name(rhs.name)
{
  tags = new uint64_t[sets*ways];
  memcpy(tags, rhs.tags, sets*ways*sizeof(uint64_t));
  //Below is construct tags into a linked list
  	LRU_block* tmp;
	LRU_block* cur;
	cur = new LRU_block;
	end = cur;
	for(size_t index = 0; index < sets*ways; index++){
		if(index == 0){
			cur->tag_mod(tags[index]);
			cur->tag_pos_mod(index);
		}
		else{
			tmp = new LRU_block;
			cur->oft_use_mod(tmp);
			tmp->less_use_mod(cur);
			tmp->tag_mod(tags[index]);
			tmp->tag_pos_mod(index);
			cur = tmp;
		}
	}
	head = cur;
}

cache_sim_t::~cache_sim_t()
{
  print_stats();
  delete [] tags;
}

/* Do not modify this function */
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
//old check_tag
uint64_t* cache_sim_t::check_tag(uint64_t addr)
{
  size_t idx = (addr >> idx_shift) & (sets-1);
  size_t tag = (addr >> idx_shift) | VALID;
  for (size_t i = 0; i < ways; i++)
    if (tag == (tags[idx*ways + i] & ~DIRTY)){
		//Refresh
		for(LRU_block* oper = head; (oper->block_less_use() != NULL); (oper = oper->block_less_use())){
			if(tag == oper->tag_contain()){
				if(oper == end){
					(oper->block_oft_use())->less_use_mod(NULL);
					end = oper->block_oft_use();
				}
				else{
					LRU_block* tmp = oper->block_less_use();
					(oper->block_oft_use())->less_use_mod(tmp);
					tmp->oft_use_mod((oper->block_oft_use()));
				}
				head->oft_use_mod(oper);
				oper->oft_use_mod(NULL);
				oper->less_use_mod(head);
				head = oper;				
			}
		}
		//End of refresh
	  return &tags[idx*ways + i];
	}
  return NULL;
}


//New victimize
uint64_t cache_sim_t::victimize(uint64_t addr){
	uint64_t victim;
	if(num > (sets*ways+1)){
		victim = end->tag_contain();
		//Add new address to head
		LRU_block* new_head;
		new_head = new LRU_block;
		new_head->less_use_mod(head);
		new_head->tag_mod(addr >> idx_shift);
		new_head->tag_pos_mod(end->tag_pos_contain());
		head = new_head;
		//End adding
		tags[end->tag_pos_contain()] = (addr >> idx_shift) | VALID;
		//Drop and edit end
		LRU_block* tmp;
		(end->block_oft_use())->less_use_mod(NULL);
		tmp = end;
		end = end->block_oft_use();
		delete tmp;
		//End drop
	}
	else{
		size_t idx = (addr >> idx_shift) & (sets-1);
 		size_t way = lfsr.next() % ways;
  		victim = tags[idx*ways + way];
		if(num == 0){
			head->tag_mod((addr >> idx_shift));
			head->tag_pos_mod((idx*ways + way));
			head->less_use_mod(end);
		}
		else{
			LRU_block* tmp;
			tmp = new LRU_block;
			head->oft_use_mod(tmp);
			tmp->less_use_mod(head);
			tmp->tag_mod((addr >> idx_shift));
			tmp->tag_pos_mod((idx*ways + way));
			head = tmp;
		} 
  		tags[idx*ways + way] = (addr >> idx_shift) | VALID;
  		num++;
	}
	return victim;
}


void cache_sim_t::access(uint64_t addr, size_t bytes, bool store)
{
/* Do not modify how it calculates read/write count */
  store ? write_accesses++ : read_accesses++;
  (store ? bytes_written : bytes_read) += bytes;

/* Do not modify how it checks cache hit */
  uint64_t* hit_way = check_tag(addr);
  if (likely(hit_way != NULL))
  {
    if (store)
      *hit_way |= DIRTY;
    return;
  }

/* Do not modify how it calculates read/write miss */
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
  	//Refresh
	for(LRU_block* oper = head; (oper->block_less_use() != NULL); (oper = oper->block_less_use())){
		if((addr >> idx_shift) == oper->tag_contain()){
			if(oper == end){
				(oper->block_oft_use())->less_use_mod(NULL);
				end = oper->block_oft_use();
			}
			else{
				LRU_block* tmp = oper->block_less_use();
				(oper->block_oft_use())->less_use_mod(tmp);
				tmp->oft_use_mod((oper->block_oft_use()));
			}
			head->oft_use_mod(oper);
			oper->oft_use_mod(NULL);
			oper->less_use_mod(head);
			head = oper;				
		}
	}
	//End of refresh
  return it == tags.end() ? NULL : &it->second;
}

uint64_t fa_cache_sim_t::victimize(uint64_t addr)
{
	if(num > sets*ways){
	  	uint64_t victim = end->tag_contain();
		//Add new address to head
		LRU_block* new_head;
		new_head = new LRU_block;
		new_head->less_use_mod(head);
		new_head->tag_mod(addr >> idx_shift);
		new_head->tag_pos_mod(end->tag_pos_contain());
		head = new_head;
		//End adding
		tags[end->tag_pos_contain()] = (addr >> idx_shift) | VALID;
		//Drop and edit end
		LRU_block* tmp;
		(end->block_oft_use())->less_use_mod(NULL);
		tmp = end;
		end = end->block_oft_use();
		delete tmp;
		//End drop
		return victim;
	}
	else{
		uint64_t old_tag = 0;
		if (tags.size() == ways)	{
		auto it = tags.begin();
		std::advance(it, lfsr.next() % ways);
		old_tag = it->second;
		tags.erase(it);
		}
		tags[addr >> idx_shift] = (addr >> idx_shift) | VALID;
		return old_tag;
	}
}
