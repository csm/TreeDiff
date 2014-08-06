/* 
   Copyright (C) 2014  Casey Marshall

This file is a part of Jessie.

Jessie is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

Jessie is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with Jessie; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
USA

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version.  */

package org.metastatic.treediff.test;

import org.junit.Assert;
import org.junit.Test;
import org.metastatic.treediff.PathTrie;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class TestPathTrie
{
    @Test
    public void testAddContains()
    {
        PathTrie trie = new PathTrie();
        Assert.assertEquals(0, trie.size());
        Assert.assertTrue(trie.add(Arrays.asList("foo", "bar", "baz")));
        Assert.assertTrue(trie.contains(Arrays.asList("foo", "bar", "baz")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar")));
        Assert.assertEquals(1, trie.size());
        System.out.println(trie);
    }

    @Test
    public void testAddParents()
    {
        PathTrie trie = new PathTrie();
        Assert.assertEquals(0, trie.size());
        Assert.assertTrue(trie.add(Arrays.asList("foo")));
        Assert.assertTrue(trie.contains(Arrays.asList("foo")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar", "baz")));
        Assert.assertEquals(1, trie.size());
        System.out.println(trie);

        Assert.assertTrue(trie.add(Arrays.asList("foo", "bar")));
        Assert.assertTrue(trie.contains(Arrays.asList("foo")));
        Assert.assertTrue(trie.contains(Arrays.asList("foo", "bar")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar", "baz")));
        Assert.assertEquals(2, trie.size());
        System.out.println(trie);

        Assert.assertTrue(trie.add(Arrays.asList("foo", "bar", "baz")));
        Assert.assertTrue(trie.contains(Arrays.asList("foo")));
        Assert.assertTrue(trie.contains(Arrays.asList("foo", "bar")));
        Assert.assertTrue(trie.contains(Arrays.asList("foo", "bar", "baz")));
        Assert.assertEquals(3, trie.size());
        System.out.println(trie);
    }

    @Test
    public void testIterator()
    {
        PathTrie trie = new PathTrie();
        trie.add(Arrays.asList("foo"));
        trie.add(Arrays.asList("foo", "bar", "baz"));
        System.out.println(trie);

        Iterator<List<String>> it = trie.iterator();
        Assert.assertTrue(it.hasNext());
        Assert.assertEquals(Arrays.asList("foo"), it.next());
        Assert.assertTrue(it.hasNext());
        Assert.assertEquals(Arrays.asList("foo", "bar", "baz"), it.next());
        Assert.assertFalse(it.hasNext());
    }

    @Test
    public void testAddRemove()
    {
        PathTrie trie = new PathTrie();
        trie.add(Arrays.asList("foo"));
        trie.add(Arrays.asList("foo", "bar", "baz"));
        trie.add(Arrays.asList("quux", "beable"));
        System.out.println(trie);

        Assert.assertTrue(trie.contains(Arrays.asList("foo")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar")));
        Assert.assertTrue(trie.contains(Arrays.asList("foo", "bar", "baz")));
        Assert.assertFalse(trie.contains(Arrays.asList("quux")));
        Assert.assertTrue(trie.contains(Arrays.asList("quux", "beable")));

        Assert.assertTrue(trie.remove(Arrays.asList("foo", "bar", "baz")));
        System.out.println(trie);
        Assert.assertTrue(trie.contains(Arrays.asList("foo")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar", "baz")));
        Assert.assertFalse(trie.contains(Arrays.asList("quux")));
        Assert.assertTrue(trie.contains(Arrays.asList("quux", "beable")));

        Assert.assertFalse(trie.remove(Arrays.asList("foo", "bar")));
        System.out.println(trie);
        Assert.assertTrue(trie.contains(Arrays.asList("foo")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar", "baz")));
        Assert.assertFalse(trie.contains(Arrays.asList("quux")));
        Assert.assertTrue(trie.contains(Arrays.asList("quux", "beable")));

        Assert.assertTrue(trie.remove(Arrays.asList("foo")));
        System.out.println(trie);
        Assert.assertFalse(trie.contains(Arrays.asList("foo")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar", "baz")));
        Assert.assertFalse(trie.contains(Arrays.asList("quux")));
        Assert.assertTrue(trie.contains(Arrays.asList("quux", "beable")));

        Assert.assertFalse(trie.remove(Arrays.asList("quux")));
        System.out.println(trie);
        Assert.assertFalse(trie.contains(Arrays.asList("foo")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar", "baz")));
        Assert.assertFalse(trie.contains(Arrays.asList("quux")));
        Assert.assertTrue(trie.contains(Arrays.asList("quux", "beable")));

        Assert.assertTrue(trie.remove(Arrays.asList("quux", "beable")));
        System.out.println(trie);
        Assert.assertFalse(trie.contains(Arrays.asList("foo")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar")));
        Assert.assertFalse(trie.contains(Arrays.asList("foo", "bar", "baz")));
        Assert.assertFalse(trie.contains(Arrays.asList("quux")));
        Assert.assertFalse(trie.contains(Arrays.asList("quux", "beable")));
    }
}
