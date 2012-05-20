# Copyright (C) 2012 Kyle Johnson <kyle@vacantminded.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# TODO:
# - Refactor/rewrite basically the whole script.
# - Stop blocking so hard when we run commands.
# - Make output interactive.

require 'net/http'
require 'rexml/document'

def weechat_init

  #
  # EDIT HERE
  #

  # Your key goes here. You *MUST* have a key for this script to do anything.
  # You can request one by visiting <http://dronebl.org/rpckey_signup>.
  #
  @rpc_key = ''

  # TODO: Make this a setting in WeeChat.

  #
  # STOP EDITING HERE
  #


  if @rpc_key == nil or @rpc_key.empty?
    Weechat.print "", "#{Weechat.prefix('error')}@rpc_key value not set in dronebl.rb"
    return WEECHAT_RC_ERROR
  end

  Weechat.register("dronebl", "Kabaka", "0.5", "MIT", "DroneBL Manager", "", "")

  # Create our buffer and set some options.
  @buffer = Weechat.buffer_new("DroneBL","buf_in_cb","","","")
  Weechat.buffer_set(@buffer, "title", "DroneBL Management Console")
  Weechat.buffer_set(@buffer, "type", "free")
  Weechat.buffer_set(@buffer, "time_for_each_line", "0")

  # Human-readable listing types.
  @types = {
    "1"   => 'Testing class',
    "2"   => 'Sample data used for heruistical analysis',
    "3"   => 'IRC spam drone (litmus/sdbot/fyle)',
    "5"   => 'Bottler (experimental)',
    "6"   => 'Unknown worm or spambot',
    "7"   => 'DDoS drone',
    "8"   => 'Open SOCKS proxy',
    "9"   => 'Open HTTP proxy',
    "10"  => 'Proxychain',
    "13"  => 'Automated dictionary attacks',
    "14"  => 'Open WINGATE proxy',
    "15"  => 'Compromised router / gateway',
    "16"  => 'Autorooting worms',
    "17"  => 'Automatically determined botnet IPs (experimental)',
    "255" => 'Uncategorized threat class'}

  # Used for the tabular output.
  @short_types = {     # 
    "1"   => 'Test Entry',
    "2"   => 'Sample',
    "3"   => 'IRC Drone',
    "5"   => 'Bottler',
    "6"   => 'Spambt/Wrm',
    "7"   => 'DDoS Drone',
    "8"   => 'SOCKS Prxy',
    "9"   => 'HTTP Proxy',
    "10"  => 'Proxychain',
    "13"  => 'DictAttcks',
    "14"  => 'WINGATE Pr',
    "15"  => 'CompRtr/Gw',
    "16"  => 'Root Worms',
    "17"  => 'Botnet',
    "255" => 'Uncategrzd'}

  show_help

  Weechat::WEECHAT_RC_OK
end

# Callback for buffer input (not slash commands).
def buf_in_cb(data, buffer, input_data)
  return Weechat::WEECHAT_RC_OK if input_data.empty?

  input_arr = input_data.split

  case input_arr.shift.downcase
  when "records"
    show_records(input_arr)
  when "remove"
    remove(input_arr)
  when "lookup"
    lookup(input_arr)
  when "add"
    add(input_arr)
  when "help"
    show_help
  when "clear"
    show_help
  when "types"
    show_types
  end

  Weechat::WEECHAT_RC_OK
end

# API call to look up addresses, address ranges, or incident IDs.
# input_arr - the string split in the buf_in_cb function.
def lookup(input_arr)

  case input_arr.shift.downcase

  when "ip"
    # IP or IP range lookup.

    if input_arr.empty?
      show_msg("Syntax: lookup ip address_or_range [active | inactive]")
      return
    end

    ip = input_arr.shift

    # We're allowed to include wildcards in the IP lookup:
    #   ? - match any single digit
    #   * - match any number of anything
    #   [n1-n2] - match anything between n1 and n2, inclusive
    # We're not checking for valid structure here (yet?). So things like
    # 999.999.999.999 or even 0000000000000000 or ... will pass.
    # Patches welcome. ;-)
    unless ip =~ /^[0-9.*-\[\]]+$/
      show_msg("ERROR: You must specify a valid IP. You may use wildcards: * ? [n1-n2]")
      return
    end

    unless input_arr.empty?
      # If the last word is "active" or "inactive" go ahead and only ask for
      # such entries.
      case input_arr.shift.downcase

      when "active"
        result = do_request("<lookup ip=\"#{ip}\" listed=\"1\" />")
      when "inactive"
        result = do_request("<lookup ip=\"#{ip}\" listed=\"0\" />")
      else
        result = do_request("<lookup ip=\"#{ip}\" />")
      end

    end

    if result == false
      show_msg("ERROR: API call failed.")
      return
    end

    print_listings(result)
    return

  when "id"
    # Incident ID lookup

    if input_arr.empty?
      show_msg("Syntax: lookup id incident_id")
      return
    end

    id = input_arr.shift
    
    unless id =~ /^[0-9]+$/
      show_msg("ERROR: Incident ID must be an integer.")
      return
    end

    result = do_request("<lookup id=\"#{id}\" />")

    if result == false
      show_msg("ERROR: API call failed.")
      return
    end

    print_listings(result)
    return
  end

  show_msg("Syntax: lookup [ip address_or_range [active | inactive] | id incident_id")
end


# API call to add a new record to DroneBL.
# input_arr - the string split in the buf_in_cb function.
def add(input_arr)
  if input_arr.length < 2
    show_msg("Syntax: add type ip_address [ip_addresses]")
    return
  end

  type = input_arr.shift

  unless is_valid_type?(type)
    show_msg("ERROR: Invalid type. To see valid listing types, enter: types")
    return
  end

  req_str = ""

  input_arr.reject! {|ip| not is_valid_ip?(ip)}

  input_arr = clear_listed_ips(input_arr)

  if input_arr.empty?
    show_msg("ERROR: No valid IPs given or all valid IPs are already in DroneBL.")
    return
  end

  input_arr.each {|ip| req_str << "<add ip=\"#{ip}\" type=\"#{type}\" />\n"}

  # No 200. Abort!
  unless do_request(req_str)
    show_msg("ERROR: API call failed.")
    return 
  end

  # Fake a call to the records command.
  show_records(["active"])
end

# API call to deactivate listings.
# input_arr - the string split in the buf_in_cb function.
def remove(input_arr)
  if input_arr.empty?
    show_msg("Syntax: remove incident_id")
    return
  end

  req_str = ""

  input_arr.each do |id|
    next unless id =~ /^[0-9]+$/

    req_str << "<remove id=\"#{id}\" />"
  end

  if req_str.empty?
    show_msg("ERROR: No valid incident IPs were given.")
    return
  end

  unless do_request(req_str)
    show_msg("ERROR: API call failed.")
    return 
  end

  # Fake a call to the records command.
  show_records([])
end

# API call to fetch records for your RPC key.
# input_arr - the string split in the buf_in_cb function.
def show_records(input_arr)
  req_str = "<records "
  type_specified, listed_specified = false, false

  input_arr.each do |arg|

    if arg == "active" and not listed_specified
      req_str << 'listed="1" '
      listed_specified = true

    elsif arg == "inactive" and not listed_specified
      req_str << 'listed="0" '
      listed_specified = true

    elsif is_valid_type?(arg) and not type_specified
      req_str << "type=\"#{arg}\" "
      type_specified = true

    end

  end

  req_str << "/>"

  result = do_request(req_str)

  if result == false
    show_msg("ERROR: API call failed.")
    return
  end

  print_listings(result)
end

# Return an array with IPs that are listed in DroneBL removed.
def clear_listed_ips(ips)
  str = ""

  ips.each {|ip| str << "<lookup ip=\"#{ip}\" limit=\"1\" listed=\"1\" />\n"}
  result = do_request(str)

  return nil unless result

  root = REXML::Document.new(result)

  root.elements.each("/response/result") do |result|
    if result.attributes['listed'] == "1"
      ips.delete result.attributes['ip']
    end
  end

  ips
end


# Populate the dronebl buffer with thhe results of a lookup
# or records call.
# result - raw XML string from the server
def print_listings(result)
  # Make room!
  Weechat.buffer_clear(@buffer)

  Weechat.print_y(@buffer, 0,
                #            1         2         3         4         5         6         7
                #  012345678901234567890123456789012345678901234567890123456789012345678901
                  "ID        IP               Type              Added (UTC)          Active")
                #  123123123  000.000.000.000  00 (xxxxxxxxxx)  0000-00-00 00:00:00  YES

  line = 1

  doc = REXML::Document.new(result)

  doc.elements.each("/response/result") do |result| 
    id = sprintf("%-10.10s", result.attributes['id']) # invident ID
    ip = sprintf("%-17.17s", result.attributes['ip']) # IP Address
    
    type = result.attributes['type']  # numerical incident type
    type_desc = get_type_desc(type) # get short type description (@short_types)

    type = sprintf("%-18.18s", "#{type} (#{type_desc})") # format as type (desc)

    # comment = sprintf("%-10.10s", result.attributes['comment'])

    # This will truncate the timezone. The header specifies we are using
    # UTC, so that is fine.
    timestamp = sprintf("%-20.20s",
                        Time.at(result.attributes['timestamp'].to_i).utc.to_s)

    if result.attributes['listed'] == "1"
      color = Weechat.color("green")
      listed = " YES"

    else
      color = Weechat.color("red")
      listed = " NO"

    end

    str = "#{color}#{id}#{ip}#{type}#{timestamp}#{listed}"

    Weechat.print_y(@buffer, line, str)

    line += 1
  end

  Weechat.print_y(@buffer, line+1, "#{line-1} records shown.")
end



# Assemble and send the request.
# query - XML string containing the request(s) to send.
def do_request(query)
  if @rpc_key == ""
    show_msg("You must set your DroneBL RPC key with /set plugins.var.dronebl.rpc_key KEY")
  end

  request_xml = "<?xml version=\"1.0\"?>
<request key='#{@rpc_key}'>
  #{query}
</request>"

  url = URI.parse("http://dronebl.org/RPC2")
  http = Net::HTTP.new(url.host, url.port)

  request = Net::HTTP::Post.new(url.path)
  request.body = request_xml
  request["Content-Type"] = "application/xml"

  response = http.request(request)

  # TODO: Parse error XML and show something meaningful to the user.
  return false unless response.code == "200"

  response.body
end

# Returns false if the given string is a valid IP. This function does pass some
# weird ones, like 0.0.0.1. Oh well. Let DroneBL deal with it!
def is_valid_ip?(str)
  str =~ /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
end

# Return true if the given listing type is valid.
def is_valid_type?(str)
  @types.has_key?(str)
end

# Get the human-readable description for a listing type, or "Unknown" if we
# don't know it.
def get_type_desc(type)
  if @short_types.has_key? type
    return @short_types[type]
  end

  "Unknown"
end

def show_help
  help_str = "
Type commands here without a slash:
  lookup [ip ip_address_or_range [active | inactive] | id incident_id]
    Look up DroneBL listings. If an IP address is used, you may use
    wildcards: * - any numbers, ? - any single number, [n1-n2] - range.

  add type ip_address
    Quickly add one or many IP addresses to DroneBL. A numerical type is
    required. For multiple IP addresses, separate by space. Only give the
    type once. All records will be added with that type.

  remove [ip ip_address | id incident_id]
    Remove an incident from DroneBL if your RPC key has the rights to do so.
    If an IP address is used, it must be absolute; the wildcards used for
    lookups are not permitted.
  
  records [type] [active | inactive]
    Get the recent entries submitted with your RPC key. You may optionally
    specify whether to retrieve only active or inactive listings.
  
  types
    Show a list of all DroneBL incident types. Deprecated types are not
    included. Only the types listed may be used for new entries."

  print_multiline(help_str)
end

def print_multiline(lines)
  Weechat.buffer_clear(@buffer)

  lines.each_line.each_with_index do |line, number|
    Weechat.print_y(@buffer, number, line) 
  end
end

def show_types
  Weechat.buffer_clear(@buffer)

  Weechat.print_y(@buffer, 0, "DroneBL Listing Types")
  Weechat.print_y(@buffer, 2, "Class  Description")

  line = 3
  @types.each_pair do |key, desc|
    Weechat.print_y(@buffer, line, "#{sprintf("%-7.7s", key)}#{desc}")
    line += 1
  end

end

def show_msg(str)
  width = Weechat.window_get_integer(Weechat.current_window(), "win_chat_width")

  Weechat.print_y(@buffer, 0, sprintf("%s%-#{width}.#{width}s", Weechat.color("red"), str))
end
