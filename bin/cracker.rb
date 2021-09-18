#!/usr/bin/env ruby

# frozen_string_literal: true

require 'safeincloud'

if ARGV.length != 2
  puts "Usage: #{__FILE__} <database> <dictionary>"
  exit
end

unless File.exist?(ARGV[0])
  puts %(Database file #{ARGV[0]} doesn't exist)
  exit
end

unless File.exist?(ARGV[1])
  puts %(Dictionary file #{ARGV[1]} doesn't exist)
  exit
end

db = SafeInCloud::Database.new(ARGV[0])
db.read_header

dictionary = File.open(ARGV[1])
password = String.new

i = 0
until dictionary.eof?
  db.password = dictionary.readline.chomp
  i += 1
  print %(\x1b[1G\x1b[2K\x1b[35m[#{i}] \x1b[33m#{db.password})
  begin
    db.decrypt_checksum
  rescue StandardError
    next
  else
    password = db.password
    break
  end
end

if password.empty?
  puts %( \x1b[31mNot found!\x1b[0m)
else
  puts %( \x1b[32mFOUND!\x1b[0m)
end

dictionary.close
