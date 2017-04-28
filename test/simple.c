/*
    simple.c -- cmocka simple unittest
    Copyright (C) 2015-2017 Rafal Lesniak

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

/* Use the unit test allocators */
#define UNIT_TESTING 1

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

//#include "config.h"
#include "system.h"

#include "splay_tree.h"
#include "conf.h"
#include "edge.h"
#include "graph.h"
#include "hash.h"
#include "node.h"
#include "xalloc.h"
#include "protocol.h"

/*
   hash tests
*/
static int hash_setup(void **state) {
  UNUSED(state);
  return 0;
}

static int hash_teardown(void **state) {
  UNUSED(state);
  return 0;
}

static void test_hash_init(void **state) {
  UNUSED(state);
  hash_t *h1 = NULL;
  node_t *n1 = NULL, *n2 = NULL, *n3 = NULL;
  h1 = hash_alloc(10, sizeof(node_t));
  init_nodes();
  n1 = new_node();
  n1->name = xstrdup("node1");
  n3 = new_node();
  n3->name = xstrdup("node3");

  assert_non_null(h1);
  assert_int_equal(h1->n, 10);
  assert_int_equal(h1->size, sizeof(node_t));
  assert_non_null(h1->keys);
  assert_non_null(h1->values);

  hash_insert(h1, "node1", n1);
  n2 = hash_search(h1, "node1");
  assert_non_null(n2);
  assert_ptr_equal(n1,n2);
  hash_delete(h1, "node1");

  n2 = hash_search(h1, "node1");
  assert_null(n2);

  hash_search_or_insert(h1, "node3", n3);

  n2 = hash_search(h1, "node3");
  assert_non_null(n2);
  assert_ptr_equal(n3,n2);

  hash_clear(h1);
  assert_int_equal(*h1->values, 0x0);

  hash_free(h1);

}

/*
   connection tests
*/
static int connection_setup(void **state) {
  UNUSED(state);
  init_connections();
  return 0;
}

static int connection_teardown(void **state) {
  UNUSED(state);
  exit_connections();
  return 0;
}

static void test_connection_init(void **state) {
  UNUSED(state);
  connection_t *c1;
  c1 = new_connection();
}

static void test_connection_graph(void **state) {
  UNUSED(state);
  connection_t *c1;
  edge_t *e1, *e2, *e3;
  node_t *n1, *n2;

  // grpah() needs nodes and edges
  init_nodes();
  init_edges();

  e1 = new_edge();
  e2 = new_edge();
  e3 = new_edge();

  myself = new_node();
  myself->name = xstrdup("node1");
  xasprintf(&myself->hostname, "MYSELF port %d", 31337);
  myself->connection = new_connection();
  myself->connection->options = 0;
  myself->connection->protocol_major = PROT_MAJOR;
  myself->connection->protocol_minor = PROT_MINOR;
  myself->connection->outcompression = 0;
  myself->connection->hostname = xstrdup(myself->hostname);

  n1 = new_node();
  n1->name = xstrdup("node2");

  n2 = new_node();
  n2->name = xstrdup("node3");

  node_add(myself);
  node_add(n1);
  node_add(n2);

  e1->from = myself;
  e1->to = n1;

  edge_add(e1);

  e2->from = n1;
  e2->to = n2;

  edge_add(e2);

  e3->from = n2;
  e3->to = myself;

  edge_add(e3);

  c1 = new_connection();

  assert_non_null(c1);
  connection_add(c1);

  graph();

  e2->weight = 10;

  edge_add(e2);
  graph();

  assert_int_equal(receive_request(c1, "nope\n"), false);
  assert_int_equal(receive_request(c1, "0 nope 0.0\n"), false);
  receive_request(c1, "0 node1 0.1\n0.0\r\n");

  receive_request(c1, "0  \n");
  receive_request(c1, "0 nodäe1 1.17\n");
  receive_request(c1, "0 node2 1.ä\n");

  // this will segfault cause cmdline_conf is NULL
  //receive_request(c1, "0 node2 17.7\n");

  connection_del(c1);
  exit_edges();
  exit_nodes();

}

/*
   node tests
*/
static int node_setup(void **state) {
  UNUSED(state);
  init_nodes();
  return 0;
}

static int node_teardown(void **state) {
  UNUSED(state);
  return 0;
}

static void test_node_init(void **state) {
  node_t *n1, *n2;
  UNUSED(state);
  n1 = new_node();
  assert_non_null(n1);
  n2 = new_node();
  assert_non_null(n2);
}

/*
   edge tests
*/
static int edge_setup(void **state) {
  UNUSED(state);
  init_edges();
  return 0;
}

static int edge_teardown(void **state) {
  UNUSED(state);
  exit_edges();
  return 0;
}


static void test_edge_init(void **state) {
  UNUSED(state);
  edge_t *e1, *e2;
  node_t *n1, *n2;

  e1 = new_edge();
  assert_non_null(e1);
  assert_null(e1->from);
  assert_null(e1->to);

  init_nodes();

  n1 = new_node();
  n2 = new_node();

  assert_null(n1->name);
  assert_null(n2->name);

  n1->name = xstrdup("node1");
  n2->name = xstrdup("node2");

  e1->from = n1;
  e1->to = n2;

  //TODO: make edge_add work on any edge_tree
  // edge_add needs from and to to be set

  //e2 = clone_edge(e1);
  e2 = new_edge();

  e2->from = n2;
  e2->to = n1;

  assert_ptr_not_equal(e1, e2);

  edge_add(e1);
  edge_add(e2);

  assert_int_equal(edge_weight_tree->count, 2);

  //TODO: make edge_del work on any edge_tree
  edge_del(e1);
  assert_int_equal(edge_weight_tree->count, 1);

  exit_nodes();

}


/*
  splay tree tests
*/

typedef struct mock_item {
  int value;
} mock_item_t;

int splay_mock_compare(const mock_item_t *a, const mock_item_t *b);
int splay_mock_compare(const mock_item_t *a, const mock_item_t *b) {
  if (a->value > b->value)
    return 1;
  return 0;
}

void splay_mock_delete(mock_item_t *);
void splay_mock_delete(mock_item_t *a) {
  test_free(a);
}

static int splay_tree_setup(void **state) {
  splay_tree_t *my_tree;
  my_tree = splay_alloc_tree((splay_compare_t) splay_mock_compare,
                             (splay_action_t) splay_mock_delete);
  *state = my_tree;
  return 0;
}

static void test_splay_tree_init(void **state) {
  splay_tree_t *my_tree = *state;

  assert_non_null(my_tree);
  assert_null(my_tree->head);
  assert_null(my_tree->tail);
  assert_null(my_tree->root);
  assert_non_null(my_tree->compare);
  assert_non_null(my_tree->delete);
  assert_int_equal(my_tree->count, 0);

  splay_delete_tree(my_tree);

}

void test_splay_tree_basic(void **);
void test_splay_tree_basic(void **state) {
  splay_tree_t *my_tree = *state;
  mock_item_t *i, *b;
  int r;
  assert_non_null(my_tree);

  i = NULL;
  b = NULL;

  for(int z=0; z < 10; z++) {
    i = xzalloc(sizeof(mock_item_t));
    assert_non_null(i);
    i->value = z;
    assert_int_equal(i->value, z);
    splay_insert(my_tree, i);
  }
  assert_int_equal(my_tree->count, 10);

  i = xzalloc(sizeof(mock_item_t));
  i->value = 7;
  b = splay_search_closest(my_tree, i, &r);
  assert_non_null(b);
  // this is a reference test for current state of splay_search algorithm
  assert_int_equal(b->value, 9);
  // cleanup local alloc
  test_free(i);

  splay_delete_tree(my_tree);

}

/*
  Config tests
*/

static int config_setup(void **state) {
  splay_tree_t *config_tree;
  init_configuration(&config_tree);
  assert_non_null(config_tree);
  *state = config_tree;

  return 0;
}

static int config_teardown(void **state) {
  splay_tree_t *config_tree = *state;
  exit_configuration(&config_tree);
  assert_null(config_tree);

  return 0;
}

static void test_read_config_file(void **state) {
  char *priority = NULL;
  splay_tree_t *config_tree = *state;

  read_config_file(config_tree, "./mocks/conf1");

  get_config_string(lookup_config(config_tree, "Ed25519PublicKey111111"), &priority);
  assert_null(priority);

  //this one triggers a memory leak
  get_config_string(lookup_config(config_tree, "Ed25519PublicKey"), &priority);
  assert_non_null(priority);
}

static void test_config_add_item(void **state) {
  splay_tree_t *config_tree = *state;
  config_t *item = NULL;
  config_t *item2;
  char *value = NULL;

  item = new_config();
  assert_non_null(item);

  item->variable = xstrdup("testVar1");
  item->value = xstrdup("barbara");
  item->file = xstrdup("none");;
  item->line = 1;

  config_add(config_tree, item);

  value = NULL;
  get_config_string(lookup_config(config_tree, "testVar1"), &value);
  assert_non_null(value);

  if (!value) {
    item2 = NULL;
    for splay_each(config_t, item2, config_tree) {
        printf("%s %s %s %d\n", item2->variable, item2->value, item2->file, item2->line);
      }
  }
}

static void test_config_add_item_no_filename(void **state) {
  splay_tree_t *config_tree = *state;
  config_t *item = NULL;
  config_t *item2;
  char *value = NULL;

  item = new_config();
  assert_non_null(item);

  item->variable = xstrdup("testVar2");
  item->value = xstrdup("barbara");
  item->file = NULL;
  item->line = -1;

  config_add(config_tree, item);

  value = NULL;
  item2 = lookup_config(config_tree, "testVar2");
  assert_non_null(item2);

  get_config_string(item2, &value);
  assert_non_null(value);
  if (!value) {
    item2 = NULL;
    for splay_each(config_t, item2, config_tree) {
        printf("%s %s %s %d\n", item2->variable, item2->value, item2->file, item2->line);
      }
  }
}

int main(void) {
  const struct CMUnitTest tests[] = {
    // hash tests
    cmocka_unit_test_setup_teardown(test_hash_init, hash_setup, hash_teardown),
    // connection tests
    cmocka_unit_test_setup_teardown(test_connection_init, connection_setup, connection_teardown),
    cmocka_unit_test_setup_teardown(test_connection_graph, connection_setup, connection_teardown),
    // cmocka_unit_test_setup_teardown(test_protocol_first, connection_setup, connection_teardown),
    // node tests
    cmocka_unit_test_setup_teardown(test_node_init, node_setup, node_teardown),
    // edge tests
    cmocka_unit_test_setup_teardown(test_edge_init, edge_setup, edge_teardown),
    // config tests
    cmocka_unit_test_setup_teardown(test_read_config_file, config_setup, config_teardown),
    cmocka_unit_test_setup_teardown(test_config_add_item, config_setup, config_teardown),
    cmocka_unit_test_setup_teardown(test_config_add_item_no_filename, config_setup, config_teardown),
    // splay_tree tests
    cmocka_unit_test_setup(test_splay_tree_init, splay_tree_setup),
    cmocka_unit_test_setup(test_splay_tree_basic, splay_tree_setup)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
