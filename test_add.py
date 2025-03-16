import pytest
@pytest.mark.parametrize(
 "a,b,c",
 [(1,2,3), (4,5,6)]
)
def test_add(a,b,c):
  assert a+b == c
