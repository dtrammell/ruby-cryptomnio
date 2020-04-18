#!/usr/bin/ruby

require 'cryptomnio'

DEBUG = true

# Create Twitter Client Object
client = Cryptomnio::REST::Client.new do |c|
	# Put all config options in a hash
	c.config = {
		# API Endpoint URL
		apiurl: "https://api.cryptomnio.com",
		# Authentication
		authtype: "Basic",
		username: "TTBot",
		password: "?????",
		apikeys:  []
	}

	# Exchange API Keys
	c.config[:apikeys].push({
			exchange: "kraken",
			key:      "",
			secret:   ""
	})
	c.config[:apikeys].push({
			exchange:  "coinbase",
			key:       "",
			secret:    "",
			passphrase: ""
	})
end

# Print Gem Info
puts "%s %s" % [ Cryptomnio::NAME, Cryptomnio::GEM_VERSION ]
puts "2020-04 - %s" % Cryptomnio::AUTHOR
puts "API Version: %s" % Cryptomnio::API_VERSION
puts

puts "Testing Authentication/BasicAuth"
client.auth_basic

puts "Testing Exchange Keys/Upload API Key"
client.upload_keys

# Test Exchange Key activation
#puts "Testing Exchange Key activation"
#client.activate_keys

# Test Crytpomnio Create New Order
#puts "Testing Order Creation"
#client.create_order # Creating something way out of market

# Test Get Single Order
#puts "Testing Get Single Order"
#client.get_single_order

# Test Cancel Order
#puts "Testing Cancel Order"
#client.cancel_order

# Test Get Active Orders
#puts "Testing Get Active Orders"
#client.get_active_orders

# Test Get Closed Orders
#puts "Testing Get Closed Orders"
#client.get_closed_orders

# Testing Get All Wallets
#puts "Testing Get All Wallets"
#client.get_all_wallets

# Test Exchange Key deactivation
#puts "Testing Exchange Key deactivation"
#client.deactivate_keys

# Test Exchange Key delete
#puts "Testing Exchange Key deletion"
#client.delete_keys

