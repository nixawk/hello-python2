#!/usr/bin/python
# -*- coding: utf-8 -*-

from searchengine import searchengine
import requests


class github(searchengine):
    def __init__(self):
        super(github, self).__init__()

    def github_api_search(self, api_url, dork, sort, order):
        """Search dorks from github pages without authentication.
        """
        # https://developer.github.com/v3/search/
        # https://help.github.com/articles/search-syntax/
        # https://help.github.com/articles/advanced-search/

        params = {'q': dork, 'sort': sort, 'order': order}
        response = requests.get(api_url, params=params)
        response_json = response.json()

        if 'total_count' in response_json:
            total_count = response_json['total_count']
        else:
            total_count = []

        if 'incomplete_results' in response_json:
            incomplete_results = response_json['incomplete_results']
        else:
            incomplete_results = []

        if 'items' in response_json:
            items = response_json['items']
        else:
            items = []

        return total_count, incomplete_results, items

    def search_repositories(self, dork, sort='stars', order='desc'):
        """Find repositories via various criteria.
        This method returns up to 100 results per page.

        param: sort: The sort field. One of stars, forks, or updated.
                     Default: results are sorted by best match.

        param order: The sort order if sort parameter is provided.
                     One of asc or desc. Default: desc
        """
        api_url = 'https://api.github.com/search/repositories'
        return self.github_api_search(api_url, dork, sort, order)

    def search_code(self, dork, sort='indexed', order='desc'):
        """Find file contents via various criteria.
        (This method returns up to 100 results per page.)

        param: sort: The sort field. Can only be indexed,
                     Which indicates how recently a file has been indexed by
                     the Github search infrastruction.
                     Default: results are sorted by best match
        """
        api_url = 'https://api.github.com/search/code'
        return self.github_api_search(api_url, dork, sort, order)

    def search_issues(self, dork, sort='updated', order='desc'):
        """Find issues by state and keyword.

        param: sort: The sort field. Can be comments, created, or updated.
                     Default: results are sorted by best match.

        param order: The sort order if sort parameter is provided.
                     One of asc or desc. Default: desc.
        """
        api_url = 'https://api.github.com/search/issues'
        return self.github_api_search(api_url, dork, sort, order)

    def search_users(self, dork, sort='followers', order='desc'):
        """Find users via various criteria.

        param: sort: The sort field. Can be followers, repositories, or joined.
                     Default: results are sorted by best match.

        param: order: The sort order if sort parameter is provided.
                      One of asc or desc. Default: desc
        """
        api_url = 'https://api.github.com/search/users'
        return self.github_api_search(api_url, dork, sort, order)


def parse_html_url(results):
    total_count, incomplete_results, items = results
    for item in items:
        print(item['html_url'])


def demo_github():
    from pprint import pprint

    gh = github()
    print('----Search repositories----')
    dork = 'rapid7 language:ruby'
    parse_html_url(gh.search_repositories(dork))

    print('----Search code----')
    dork = 'upload_file in:file language:ruby repo:rapid7/metasploit-framework'
    parse_html_url(gh.search_code(dork))

    print('----Search issues----')
    dork = 'dirtycow label:feature language:ruby state:open'
    parse_html_url(gh.search_issues(dork))

    print('----Search users----')
    dork = 'rapid7'
    parse_html_url(gh.search_users(dork))

if __name__ == '__main__':
    demo_github()
