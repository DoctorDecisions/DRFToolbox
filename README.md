# DRFToolbox

Contained within this library are a set of utility modules and functions,
specific to the [Django Rest Framework](https://github.com/encode/django-rest-framework/),
that our team finds useful for developing APIs.

[![CircleCI](https://circleci.com/gh/DoctorDecisions/DRFToolbox.svg?style=svg&circle-token=a9cf2a90de69cdbcb919d58cd73c25f7e77f7ad8)](https://circleci.com/gh/DoctorDecisions/DRFToolbox)
[![Coverage Status](https://coveralls.io/repos/github/DoctorDecisions/DRFToolbox/badge.svg?t=ySeEKr)](https://coveralls.io/github/DoctorDecisions/DRFToolbox)

## Development

  * initialize the environment for development
    *(install deps and upgrade)
    ```
    make init
    ```
  * install all required packages
    *(install exact deps listed in lock file)
    ```
    make build
    ```
  * run test cases
    ```
    make test
    ```
  * run test cases with coverage report
    ```
    make coverage
    ```
  * run pylint
    ```
    make lint
    ```
  * remove all compiled python files
    ```
    make clean
    ```
  * create and push a new release tag
    ```
    make tag
    ```
