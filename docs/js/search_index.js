var search_data = {"index":{"searchIndex":["cryptomnio","rest","client","httpclient","loghttprequest","object",":get,()","_check_errors()","_rest_call()","auth_basic()","auth_cryptomnio()","auth_cryptomnio_test()","create_venue_account_order_limit()","create_venue_account_order_market()","delete_venue_account_order()","geminfo()","get()","get()","initalize()","initalize()","initalize()","new()","retrieve_venue_account()","retrieve_venue_account_balance()","retrieve_venue_account_balance_symbol()","retrieve_venue_account_order()","retrieve_venue_account_orders()","retrieve_venue_account_trade()","retrieve_venue_account_trades()","retrieve_venue_market_orderbook()","retrieve_venue_market_ticker()","retrieve_venue_market_tickers()","retrieve_venue_markets()","retrieve_venues()","cryptomnio.rb.backup","test_cryptomnio.rb.backup"],"longSearchIndex":["cryptomnio","cryptomnio::rest","cryptomnio::rest::client","httpclient","loghttprequest","object","cryptomnio::rest::client#:get,()","cryptomnio::rest::client#_check_errors()","cryptomnio::rest::client#_rest_call()","cryptomnio::rest::client#auth_basic()","cryptomnio::rest::client#auth_cryptomnio()","cryptomnio::rest::client#auth_cryptomnio_test()","cryptomnio::rest::client#create_venue_account_order_limit()","cryptomnio::rest::client#create_venue_account_order_market()","cryptomnio::rest::client#delete_venue_account_order()","cryptomnio#geminfo()","httpclient#get()","loghttprequest#get()","cryptomnio#initalize()","cryptomnio::rest#initalize()","httpclient#initalize()","cryptomnio::rest::client::new()","cryptomnio::rest::client#retrieve_venue_account()","cryptomnio::rest::client#retrieve_venue_account_balance()","cryptomnio::rest::client#retrieve_venue_account_balance_symbol()","cryptomnio::rest::client#retrieve_venue_account_order()","cryptomnio::rest::client#retrieve_venue_account_orders()","cryptomnio::rest::client#retrieve_venue_account_trade()","cryptomnio::rest::client#retrieve_venue_account_trades()","cryptomnio::rest::client#retrieve_venue_market_orderbook()","cryptomnio::rest::client#retrieve_venue_market_ticker()","cryptomnio::rest::client#retrieve_venue_market_tickers()","cryptomnio::rest::client#retrieve_venue_markets()","cryptomnio::rest::client#retrieve_venues()","",""],"info":[["Cryptomnio","","Cryptomnio.html","","<p>This is the root Cryptomnio object Class.  It contains global constants.\n"],["Cryptomnio::REST","","Cryptomnio/REST.html","","<p>This is the root Cryptomnio REST object Class.\n<p>It inherets from the Cryptomnio object Class and contains …\n"],["Cryptomnio::REST::Client","","Cryptomnio/REST/Client.html","","<p>This is the Cryptomnio REST Client object Class\n<p>It inherets from the Cryptomnio::REST object Class and …\n"],["HTTPClient","","HTTPClient.html","","<p>HTTPClient Class Wrapper\n"],["LogHTTPRequest","","LogHTTPRequest.html","","<p>HTTP Request Logging module for HTTPClient decoration\n"],["Object","","Object.html","",""],[":get,","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-3Aget-2C","","<p>res = RestClient::Request.execute(\n\n<pre>url:                @config[:apiurl] + &quot;/&quot;,\nheaders:    { &quot;Authorization&quot; ...</pre>\n"],["_check_errors","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-_check_errors","( response, thisfailure )","<p>Error-handling method\n"],["_rest_call","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-_rest_call","( method = :get, api = :core, uripath = \"/\", uriparameters = nil, error_string = \"REST API Call Failed\", body = nil )","<p>Generic REST API call method Provides RestClient call with needed\nauthentication headers and error handling …\n"],["auth_basic","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-auth_basic","()","<p>Basic Authentication\n"],["auth_cryptomnio","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-auth_cryptomnio","( method, uripath )","<p>Cryptomnio Key Authentication\n"],["auth_cryptomnio_test","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-auth_cryptomnio_test","()","<p>Test method wrapper for Cryptomnio Key Authentication\n"],["create_venue_account_order_limit","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-create_venue_account_order_limit","( venue, accountid, venuekeyid, side, quantity, price, market )","<p>Create a new limit order under a venue account\n"],["create_venue_account_order_market","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-create_venue_account_order_market","( venue, accountid, venuekeyid, side, quantity, market )","<p>Create a new market order under a venue account\n"],["delete_venue_account_order","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-delete_venue_account_order","( venue, accountid, venuekeyid, orderid )","<p>Delete (cancel) a venue account&#39;s open order\n"],["geminfo","Cryptomnio","Cryptomnio.html#method-i-geminfo","()",""],["get","HTTPClient","HTTPClient.html#method-i-get","(*args)",""],["get","LogHTTPRequest","LogHTTPRequest.html#method-i-get","(url)",""],["initalize","Cryptomnio","Cryptomnio.html#method-i-initalize","()","<p>Creates a new Cryptomnio object\n"],["initalize","Cryptomnio::REST","Cryptomnio/REST.html#method-i-initalize","()","<p>Creates a new Cryptomnio::REST object.\n<p>If “http_proxy” is set in the program&#39;s environment, …\n"],["initalize","HTTPClient","HTTPClient.html#method-i-initalize","(client = RestClient)",""],["new","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-c-new","()","<p>Object initialization\n"],["retrieve_venue_account","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_account","( venue, accountid )","<p>Return a hash of a venue account\n"],["retrieve_venue_account_balance","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_account_balance","( venue, accountid, venuekeyid )","<p>Return an array of hashes of a venue account&#39;s balances\n"],["retrieve_venue_account_balance_symbol","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_account_balance_symbol","( venue, accountid, venuekeyid, symbol )","<p>Get account balance for symbol\n"],["retrieve_venue_account_order","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_account_order","( venue, accountid, venuekeyid, orderid )","<p>Return an hash of a venue account&#39;s single order\n"],["retrieve_venue_account_orders","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_account_orders","( venue, accountid, venuekeyid, *statuses )","<p>Return an array of hashes of a venue account&#39;s orders Accepts optional\nparameters for orders statuses …\n"],["retrieve_venue_account_trade","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_account_trade","( venue, accountid, venuekeyid, tradeid )","<p>Return a hashe of a venue account&#39;s trade\n"],["retrieve_venue_account_trades","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_account_trades","( venue, accountid, venuekeyid )","<p>Return an array of hashes of a venue account&#39;s trades\n"],["retrieve_venue_market_orderbook","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_market_orderbook","( venue, market, side = nil, limit = nil )","<p>Return a hash of a venue market&#39;s order book\n"],["retrieve_venue_market_ticker","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_market_ticker","( venue, market )","<p>Return a venue market&#39;s most current ticker hash\n"],["retrieve_venue_market_tickers","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_market_tickers","( venue, market, from = (Time.now - 60).to_i, to = nil, cursor = nil )","<p>Return an array of a venue market&#39;s ticker hashes\n"],["retrieve_venue_markets","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venue_markets","( venue )","<p>Return an array of hashes of a venue&#39;s markets\n"],["retrieve_venues","Cryptomnio::REST::Client","Cryptomnio/REST/Client.html#method-i-retrieve_venues","()","<p>Return an array of supported Venues\n"],["cryptomnio.rb.backup","","lib/cryptomnio_rb_backup.html","","<p>require &#39;rest-client&#39; require &#39;base64&#39; require\n&#39;json&#39;\n<p>## # This is the root Cryptomnio …\n"],["test_cryptomnio.rb.backup","","test/test_cryptomnio_rb_backup.html","","<p>#!/usr/bin/ruby\n<p>require &#39;cryptomnio&#39; require &#39;benchmark&#39; require\n&#39;pp&#39;\n<p>DEBUG = true …\n"]]}}