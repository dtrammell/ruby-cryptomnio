#!/bin/bash

rm *.gem
rdoc --op=docs lib test
gem build cryptomnio.gemspec
gem install *.gem
