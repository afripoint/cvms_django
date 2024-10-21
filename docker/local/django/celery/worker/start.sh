#!/bin/bash

set -o errexit
set -o nounset

exec watchfiles --filter python celery.__main__.main --args '-A api.celery_app worker -l INFO'