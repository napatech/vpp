/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * counter.c: simple and packet/byte counters
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>

void
vlib_clear_simple_counters (vlib_simple_counter_main_t * cm)
{
  counter_t *my_counters;
  uword i, j;

  for (i = 0; i < vec_len (cm->counters); i++)
    {
      my_counters = cm->counters[i];

      for (j = 0; j < vec_len (my_counters); j++)
	{
	  my_counters[j] = 0;
	}
    }
}

void
vlib_clear_combined_counters (vlib_combined_counter_main_t * cm)
{
  vlib_counter_t *my_counters;
  uword i, j;

  for (i = 0; i < vec_len (cm->counters); i++)
    {
      my_counters = cm->counters[i];

      for (j = 0; j < vec_len (my_counters); j++)
	{
	  my_counters[j].packets = 0;
	  my_counters[j].bytes = 0;
	}
    }
}

void *vlib_stats_push_heap (void *) __attribute__ ((weak));
void *
vlib_stats_push_heap (void *unused)
{
  return 0;
};

void vlib_stats_pop_heap (void *, void *, u32, int) __attribute__ ((weak));
void
vlib_stats_pop_heap (void *notused, void *notused2, u32 i, int type)
{
};

void
vlib_validate_simple_counter (vlib_simple_counter_main_t * cm, u32 index)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;
  void *oldheap = vlib_stats_push_heap (cm->counters);

  vec_validate (cm->counters, tm->n_vlib_mains - 1);
  for (i = 0; i < tm->n_vlib_mains; i++)
    vec_validate_aligned (cm->counters[i], index, CLIB_CACHE_LINE_BYTES);

  vlib_stats_pop_heap (cm, oldheap, index,
		       2 /* STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE */ );
}

void
vlib_validate_combined_counter (vlib_combined_counter_main_t * cm, u32 index)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;
  void *oldheap = vlib_stats_push_heap (cm->counters);

  vec_validate (cm->counters, tm->n_vlib_mains - 1);
  for (i = 0; i < tm->n_vlib_mains; i++)
    vec_validate_aligned (cm->counters[i], index, CLIB_CACHE_LINE_BYTES);

  vlib_stats_pop_heap (cm, oldheap, index,
		       3 /*STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED */ );
}

u32
vlib_combined_counter_n_counters (const vlib_combined_counter_main_t * cm)
{
  ASSERT (cm->counters);
  return (vec_len (cm->counters[0]));
}

u32
vlib_simple_counter_n_counters (const vlib_simple_counter_main_t * cm)
{
  ASSERT (cm->counters);
  return (vec_len (cm->counters[0]));
}

void
serialize_vlib_simple_counter_main (serialize_main_t * m, va_list * va)
{
  clib_warning ("unimplemented");
}

void
unserialize_vlib_simple_counter_main (serialize_main_t * m, va_list * va)
{
  clib_warning ("unimplemented");
}

void
serialize_vlib_combined_counter_main (serialize_main_t * m, va_list * va)
{
  clib_warning ("unimplemented");
}

void
unserialize_vlib_combined_counter_main (serialize_main_t * m, va_list * va)
{
  clib_warning ("unimplemented");
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
