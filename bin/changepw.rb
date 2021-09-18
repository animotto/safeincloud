#!/usr/bin/env ruby

# frozen_string_literal: true

require 'io/console'
require 'safeincloud'

if ARGV.empty?
  puts %(Usage: #{__FILE__} <database>)
  exit
end

unless File.exist?(ARGV[0])
  puts %(Database file #{ARGV[0]} doesn't exist)
  exit
end

print 'Password: '
$stdin.echo = false
password = $stdin.gets.chomp
puts
$stdin.echo = true

db = SafeInCloud::Database.new(ARGV[0])
db.password = password
begin
  data = db.load
rescue SafeInCloud::DatabaseError => e
  puts e
  exit
end

print 'New password: '
$stdin.echo = false
new_password = $stdin.gets.chomp
puts
$stdin.echo = true
print 'Repeat new password: '
$stdin.echo = false
repeat_new_password = $stdin.gets.chomp
puts
$stdin.echo = true
if new_password != repeat_new_password
  puts 'New password mismatch!'
  exit
end

db.password = new_password
db.save(data)
puts 'Password has been changed!'
