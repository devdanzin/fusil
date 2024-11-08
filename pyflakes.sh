#!/bin/bash
pyflakes $(find fusil -name "*.py") examples/* fuzzers/fusil-* fuzzers/notworking/fusil-*
