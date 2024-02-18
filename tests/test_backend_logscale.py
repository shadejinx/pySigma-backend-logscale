import pytest
from sigma.collection import SigmaCollection
from sigma.backends.logscale import logscaleBackend

@pytest.fixture
def logscale_backend():
    return logscaleBackend()

# TODO: implement tests for some basic queries and their expected results.
def test_logscale_and_expression(logscale_backend : logscaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['<insert expected result here>']

def test_logscale_or_expression(logscale_backend : logscaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['<insert expected result here>']

def test_logscale_and_or_expression(logscale_backend : logscaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['<insert expected result here>']

def test_logscale_or_and_expression(logscale_backend : logscaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['<insert expected result here>']

def test_logscale_in_expression(logscale_backend : logscaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['<insert expected result here>']

def test_logscale_regex_query(logscale_backend : logscaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['<insert expected result here>']

def test_logscale_cidr_query(logscale_backend : logscaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['<insert expected result here>']

def test_logscale_field_name_with_whitespace(logscale_backend : logscaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ['<insert expected result here>']

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.


