#!/usr/bin/python
# -*- coding: utf-8 -*-

# scrapy runspider quotes_spider.py -o quotes.json

# When you ran the command [scrapy runspider quotes_spider.py], Scrapy looked for a Spider definition inside
# it and ran it through its crawler engine.

# Note: This is using feed exports to generate the JSON file, you can easily change the export format (XML or CSV, for example)
# or the storage backend (FTP or Amazon S3, for example). You can also write an item pipeline to store the items in a database.

import scrapy


class QuptesSpider(scrapy.Spider):
    name = "quotes"

    # The crawl started by making requests to the URLs defined in the start_urls
    # attribute (in this case, only the URL for quotes in humor category) and called
    # the default callback method parse, passing the response object as an argument.
    # In the parse callback, we loop through the quote elements using a CSS Selector,
    # yield a Python dict with the extracted quote text and author, look for a link
    # to the next page and schedule another request using the same parse method as callback.
    start_urls = [
        'http://quotes.toscrape.com/tag/humor/'
    ]

    def parse(self, response):
        for quote in response.css('div.quote'):
            yield {
                'text': quote.css('span.text::text').extract_first(),
                'author': quote.xpath('span/small/text()').extract_first()
            }

        next_page = response.css('li.next a::attr("href")').extract_first()
        if next_page is not None:
            next_page = response.urljoin(next_page)
            yield scrapy.Request(next_page, callback=self.parse)

# Here you notice one of the main advantages about Scrapy: requests are scheduled and processed asynchronously.
# This means that Scrapy doesn't need to wait for a request to be finished and processed, it can send request or
# do other things in the meantime. This also means that other requests can keep going even if some fails or an
# error happens while handling it.

# While this enable you to do very fast crawls (sending multiple concurrent requests at the same time, in a fault-tolerant way)
# Scrapy also gives you control over the politeness of the crawl through a few settings. You can do things like settings a download
# delay between each request, limiting amount of concurrent requests per domain or per IP, and even using an auto-throttling extension
# that tries to figure out these automatically.
