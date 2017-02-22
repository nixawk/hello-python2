import scrapy
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor


class MySpiderItem(scrapy.Item):
    author = scrapy.Field()


class MySpider(CrawlSpider):
    name = 'quotes.toscrape.com'
    allowed_domains = ['toscrape.com']
    start_urls = ['http://quotes.toscrape.com/tag/humor/']

    rules = (
        # Extract links matching 'category.php' (but not matching 'subsection.php')
        # and follow links from them (since no callback means follow=True by default).
        # Extract links matching 'item.php' and parse them with the spider's method parse_item
        Rule(LinkExtractor(allow=(r'/tag/.*',), deny=(r'/login',)), callback='parse_item'),
    )

    def parse_item(self, response):
        self.logger.info('Hi, this is an item page! %s', response.url)

        item = MySpiderItem()
        author = response.xpath('//small[@class="author"]/text()').extract_first()
        item['author'] = author
        yield item
