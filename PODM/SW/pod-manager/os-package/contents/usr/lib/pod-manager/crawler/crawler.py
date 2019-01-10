# Copyright (c) 2016-2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import sys

from controller.script_controller import ScriptController


def init_parser():
    parser = argparse.ArgumentParser()
    sub_parsers = parser.add_subparsers(dest='operation_name')

    sub_parser_crawl = sub_parsers.add_parser('crawl')
    sub_parser_crawl.add_argument('--remote')
    sub_parser_crawl.add_argument('--minimal', action='store_true')
    sub_parser_crawl.add_argument('--parse_log', action='store_true')
    sub_parser_crawl.add_argument('output_file_name')

    sub_parser_mock = sub_parsers.add_parser('mock')
    sub_parser_mock.add_argument('input_file_name')
    sub_parser_mock.add_argument('starting_port')

    return parser


def main():
    parser = init_parser()
    arguments = parser.parse_args()

    if arguments.operation_name is None:
        parser.print_help()
        sys.exit()

    method = getattr(ScriptController, arguments.operation_name)
    method(arguments)

if __name__ == '__main__':
    main()
