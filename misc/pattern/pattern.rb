#!/usr/bin/env ruby

# From : rapid7/metasploit-framework

LowerAlpha = 'abcdefghijklmnopqrstuvwxyz'
UpperAlpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
Numerals   = '0123456789'

def converge_sets(sets, idx, offsets, length) # :nodoc:
  buf = sets[idx][offsets[idx]].chr

  # If there are more sets after use, converge with them.
  print(sets, idx + 1)
  print("\n")

  if (sets[idx + 1])
    buf << converge_sets(sets, idx + 1, offsets, length)
  else
    # Increment the current set offset as well as previous ones if we
    # wrap back to zero.

    while (idx >= 0 and ((offsets[idx] = (offsets[idx] + 1) % sets[idx].length)) == 0)
      idx -= 1
    end

    # If we reached the point where the idx fell below zero, then that
    # means we've reached the maximum threshold for permutations.
    if (idx < 0)
      return buf
    end

  end

  buf
end

def pattern_create(length, sets = nil)
  buf = ''
  offsets = []

  # Make sure there's something in sets even if we were given an explicit nil
  sets ||= [ UpperAlpha, LowerAlpha, Numerals ]

  # Return stupid uses
  return "" if length.to_i < 1
  return sets[0][0].chr * length if sets.size == 1 and sets[0].size == 1

  sets.length.times { offsets << 0 }

  until buf.length >= length
      buf << converge_sets(sets, 0, offsets, length)
  end

  buf[0,length]
end

def pattern_offset(pattern, value, start=0)
  if value.kind_of?(String)
    pattern.index(value, start)
  elsif value.kind_of?(Integer)
    pattern.index([ value ].pack('V'), start)
  else
    raise ::ArgumentError, "Invalid class for value: #{value.class}"
  end
end

# puts pattern_create(16)
# pattern_offset(pattern_create(50), 'Aa9A')