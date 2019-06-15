#!/usr/bin/env python3

import argparse
import csv
import logging
import re
import sys

from html.parser import HTMLParser


class WeleakinfoToCsvParser(HTMLParser):

  userList = []
  currentUser = {}
  record = False
  regex = re.compile(r'([A-Za-z\s]*):\s*(.+)')
  allAttrs = []
  attrToShow = '*'

  def change_attrs(self, attrToShow = '*'):
    self.attrToShow = attrToShow

  def handle_starttag(self, tag, attrs):
    if tag == 'div' and ('class', 'card-body') in attrs:
      self.record = True
      self.currentUser = {}

  def handle_endtag(self, tag):
    # print("Encountered an end tag :", tag)
    if tag == 'div' and self.record:
      self.record = False
      self.userList.append(self.currentUser)

  def handle_data(self, data):
    # print("Encountered some data  :", data)
    data = data.strip()
    if self.record and data != '':
      matches = self.regex.findall(data)
      if len(matches) > 1:
        logging.critical('CRITICAL error: more than one matche on the following data.\nIt may indicate a change in the webpage.')
        sys.exit(1)
      elif len(matches) == 0:
        return
      typeInfo = matches[0][0]
      valueInfo = matches[0][1]
      if self.attrToShow == '*' or (type(self.attrToShow) is list and typeInfo in self.attrToShow):
        self.currentUser[typeInfo] = valueInfo
        if typeInfo not in self.allAttrs:
          self.allAttrs.append(typeInfo)
      else:
        logging.debug('do you want to register this one? {} = {}'.format(typeInfo, valueInfo))

  def export_headers(self):
    for attr in self.allAttrs:
      print('* {}'.format(attr))

  def export_users(self):
    logging.debug('allAttrs = {}'.format(self.allAttrs))
    csvWriter = csv.DictWriter(sys.stdout, fieldnames=self.allAttrs)
    csvWriter.writeheader()
    for user in self.userList:
      logging.debug('userAttrs = {}'.format(user))
      csvWriter.writerow(user)


def main():
  argParser = argparse.ArgumentParser(description='Parse a web page from WeLeakInfo.com and output juicy info to CSV format.')
  argParser.add_argument('files', nargs='+', help='WeLeakInfo.com web page to parse')
  argParser.add_argument('-c', '--columns', dest='columns', help='Select columns to show')
  argParser.add_argument('-s', '--show', dest='show', help='Only show headers to later use -c option', action='store_true')
  argParser.add_argument('-v', '--verbose', dest='verbosity', help='Turn on debug mode', action='store_true')
  args = argParser.parse_args()

  logger = logging.getLogger()
  handler = logging.StreamHandler(sys.stdout)
  if args.verbosity:
      logger.setLevel(logging.DEBUG)
  else:
      logger.setLevel(logging.INFO)
  formatter = logging.Formatter(fmt='%(asctime)-19s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d_%H:%M:%S')
  handler.setFormatter(formatter)
  logger.addHandler(handler)

  parser = WeleakinfoToCsvParser()
  if args.columns:
    parser.change_attrs(attrToShow=args.columns.split(','))
  for fil in args.files:
    logging.debug('Parsing {}'.format(fil))
    with open(fil, 'r') as f:
      parser.feed(''.join(f.readlines()))
  if args.show:
    parser.export_headers()
  else:
    parser.export_users()



if __name__ == "__main__":
  main()
