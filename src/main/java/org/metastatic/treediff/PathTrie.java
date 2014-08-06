package org.metastatic.treediff;

import com.google.common.base.Preconditions;
import com.google.common.collect.Iterators;

import java.util.*;
import java.util.stream.Collectors;

public class PathTrie implements Set<List<String>>
{
    private class Entry implements Comparable<Entry>
    {
        private final String value;
        private boolean included;
        private final SortedSet<Entry> children;

        private Entry(String value, boolean included)
        {
            Preconditions.checkNotNull(value);
            this.value = value;
            this.included = included;
            this.children = new TreeSet<>();
        }

        private Entry(String value)
        {
            this(value, false);
        }

        void addChild(Entry e)
        {
            this.children.add(e);
        }

        void removeChild(Entry e)
        {
            this.children.remove(e);
        }

        void setIncluded(boolean included)
        {
            this.included = included;
        }

        int size()
        {
            return children.stream().mapToInt(Entry::size).sum() + (included ? 1 : 0);
        }

        Iterator<List<String>> iterator()
        {
            Iterator<List<String>> self;
            if (included)
                self = Collections.singleton(Collections.singletonList(value)).iterator();
            else
                self = Collections.emptyIterator();
            Iterator<List<String>> childIterators = Iterators.concat(children.stream().map(Entry::iterator).iterator());
            return Iterators.concat(self, Iterators.transform(childIterators, (l) -> {
                List<String> ret = new ArrayList<>(l.size() + 1);
                ret.add(value);
                ret.addAll(l);
                return ret;
            }));
        }

        boolean contains(List<String> seq)
        {
            if (seq.size() == 0)
                return false;
            else if (seq.size() == 1)
                return value.equals(seq.get(0)) && included;
            else
                return value.equals(seq.get(0)) && children.stream().anyMatch((e) -> e.contains(seq.subList(1, seq.size())));
        }

        @Override
        public int compareTo(Entry that)
        {
            return this.value.compareTo(that.value);
        }

        @Override
        public boolean equals(Object that)
        {
            return that instanceof Entry && this.value.equals(((Entry) that).value);
        }

        @Override
        public String toString()
        {
            return value;
        }
    }

    private final SortedSet<Entry> roots;

    public PathTrie()
    {
        roots = new TreeSet<>();
    }

    @Override
    public int size()
    {
        return roots.stream().mapToInt(Entry::size).sum();
    }

    @Override
    public boolean isEmpty()
    {
        return size() == 0;
    }

    @Override
    public boolean contains(Object o)
    {
        if (o instanceof List && ((List) o).stream().allMatch(e -> e instanceof String))
        {
            return roots.stream().anyMatch(e -> e.contains((List<String>) o));
        }
        return false;
    }

    @Override
    public Iterator<List<String>> iterator()
    {
        return Iterators.concat(roots.stream().map(Entry::iterator).iterator());
    }

    @Override
    public Object[] toArray()
    {
        List ret = new ArrayList(size());
        ret.addAll(this.stream().collect(Collectors.toList()));
        return ret.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a)
    {
        List<List<String>> ret = new ArrayList<>(size());
        ret.addAll(this.stream().collect(Collectors.toList()));
        return ret.toArray(a);
    }

    @Override
    public boolean add(List<String> strings)
    {
        Preconditions.checkNotNull(strings);
        Preconditions.checkArgument(strings.size() > 0);
        SortedSet<Entry> current = roots;
        boolean modified = false;
        Iterator<String> it = strings.iterator();
        while (it.hasNext())
        {
            String string = it.next();
            Optional<Entry> existing = current.stream().filter(e -> e.value.equals(string)).findFirst();
            if (existing.isPresent())
            {
                if (!it.hasNext())
                {
                    if (!existing.get().included)
                    {
                        existing.get().setIncluded(true);
                        modified = true;
                    }
                }
                current = existing.get().children;
            }
            else
            {
                modified = true;
                Entry e = new Entry(string, !it.hasNext());
                current.add(e);
                current = e.children;
            }
        }
        return modified;
    }

    @Override
    public boolean remove(Object o)
    {
        Preconditions.checkNotNull(o);
        Preconditions.checkArgument(o instanceof List);
        List<String> item = (List<String>) o;
        Preconditions.checkArgument(item.size() > 0);
        boolean modified = false;
        SortedSet<Entry> current = roots;
        Iterator<String> it = item.iterator();
        LinkedList<Entry> entries = new LinkedList<>();

        // Build a backwards path of entries.
        while (it.hasNext())
        {
            String string = it.next();
            Optional<Entry> existing = current.stream().filter(e -> e.value.equals(string)).findFirst();

            // If we don't have a particular element, nothing to remove.
            if (!existing.isPresent())
                return false;
            entries.addFirst(existing.get());
            current = existing.get().children;
        }

        // If we don't have this path, we aren't removing anything.
        if (!entries.getFirst().included)
            return false;

        // Mark the last entry as not included.
        entries.getFirst().included = false;

        // Delete entries that are not included and are empty.
        Entry e = entries.removeFirst();
        while (!entries.isEmpty() && e.children.isEmpty() && !e.included)
        {
            entries.getFirst().children.remove(e);
            e = entries.removeFirst();
            if (entries.isEmpty() && e.children.isEmpty() && !e.included)
                roots.remove(e);
        }

        return true;
    }

    @Override
    public boolean containsAll(Collection<?> c)
    {
        return c.stream().allMatch(this::contains);
    }

    @Override
    public boolean addAll(Collection<? extends List<String>> c)
    {
        return c.stream().map(e -> {
            if (contains(e)) return false;
            add(e);
            return true;
        }).anyMatch(result -> result);
    }

    @Override
    public boolean retainAll(Collection<?> c)
    {
        int s = size();
        stream().filter(e -> !c.contains(e)).forEach(this::remove);
        return size() != s;
    }

    @Override
    public boolean removeAll(Collection<?> c)
    {
        return c.stream().map(e -> {
            if (contains(e))
            {
                remove(e);
                return true;
            }
            return false;
        }).anyMatch(r -> r);
    }

    @Override
    public void clear()
    {
        roots.clear();
    }

    @Override
    public String toString()
    {
        return "[" + stream().map(e -> e.toString()).collect(Collectors.joining(", ")) + "]";
    }

    @Override
    public boolean equals(Object obj)
    {
        return obj instanceof PathTrie && this.containsAll((PathTrie) obj) && ((PathTrie) obj).containsAll(this);
    }
}
