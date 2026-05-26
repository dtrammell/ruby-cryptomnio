# ruby-cryptomnio

A Ruby gem providing a robust interface to the Cryptomnio API, allowing interaction with various cryptocurrency venues and markets. This gem simplifies authentication, request signing, and error handling for the Cryptomnio API.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'cryptomnio'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install cryptomnio

## Dependencies

*   `rest-client` (~> 2.1) - A simple HTTP and REST client for Ruby.
*   `openssl` - For cryptographic operations (HMAC SHA-512 for authentication).
*   `base64` - For Base64 encoding.
*   `json` - For JSON parsing.

## Ruby Version Requirements

This gem requires Ruby version `>= 3.3`.

## Usage

### Configuration

Before making API calls, you need to configure the client with your Cryptomnio API credentials and contexts.

```ruby
require 'cryptomnio'

client = Cryptomnio::REST::Client.new do |config|
  config.config = {
    :api_host_core => "core.cryptomnio.com",
    :api_host_cma  => "cma.cryptomnio.com",
    :authtype      => "Cryptomnio",
    :access_key    => ENV['CRYPTOMNIO_ACCESS_KEY'], # Your Cryptomnio Access Key
    :secret_key    => ENV['CRYPTOMNIO_SECRET_KEY'], # Your Cryptomnio Secret Key
    :contexts      => {
      :default => {
        :venue      => "exchange-name", # e.g., "binance"
        :accountid  => "your-account-id",
        :venuekeyid => "your-venue-key-id"
      }
    }
  }
end

# Switch to the default context
client.context_switch(:default)
```

### Example API Calls

#### Get Supported Venues

```ruby
venues = client.get_venues
puts "Supported Venues: \#{venues.inspect}"
```

#### Get Market Orderbook

```ruby
orderbook = client.get_market_orderbook(market: "BTC-USD", venue: "exchange-name")
puts "Market Orderbook: \#{orderbook.inspect}"
```

## Contributing

Bug reports and pull requests are welcome on GitHub.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Further Documentation

Comprehensive API documentation is generated and available [here](https://dtrammell.github.io/ruby-cryptomnio/).
