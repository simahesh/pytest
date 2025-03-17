'''
Using pytest fixture, opening a file for test cvase and closing it in the end of test run.
Need not to open close file for individual test case
'''
import pytest

@pytest.fixture(scope='module')
def file_h(request):
   f1=open('test_file.txt','w+')

   def file_c():
     f1.close()
   
   request.addfinalizer(file_c)
   return f1

def test_write(file_h):
  file_h.write('20 chars are written')
  file_h.seek(0)
  read = len(file_h.read())
  assert read == 20

def test_truncate(file_h):
  file_h.seek(15)
  file_h.truncate()
  file_h.seek(0)
  read = len(file_h.read())
  assert read == 15
