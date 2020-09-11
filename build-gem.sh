#!/bin/bash

rm *.gem
gem build cryptomnio.gemspec
gem install *.gem
