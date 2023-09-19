def partial(func, *part_args):
  def wrapper(*extra_args):
    args = list(part_args)
    args.extend(extra_args)
    return func(*args)

  return wrapper

def sum2(a,b,c):
  print(a)
  return a+b+c




print(partial(sum2, 423123123)(2,123123))
print(sum2( 423123123,2,123))


from functools import partial

class memoize(object):
  """cache the return value of a method

  This class is meant to be used as a decorator of methods. The return value
  from a given method invocation will be cached on the instance whose method
  was invoked. All arguments passed to a method decorated with memoize must
  be hashable.

  If a memoized method is invoked directly on its class the result will not
  be cached. Instead the method will be invoked like a static method:
  class Obj(object):
      @memoize
      def add_to(self, arg):
          return self + arg
  Obj.add_to(1) # not enough arguments
  Obj.add_to(1, 2) # returns 3, result is not cached
  """
  def __init__(self, func):
    self.func = func
  def __get__(self, obj, objtype=None):#使用注解修饰inc_add函数之后，当调用inc_add函数的时候就会触发注解类的__get__函数，同时test类会作为第二个参数被传进来，传进来之后会使用functools.partial进行装饰，在最上面有一个我们手动实现的partial函数，工作机制和functools.partial是一致的，使用partial装饰完成之后，inc_add其实就不是inc_add了，而是已经被装饰过的另一个函数，他偷偷地加了一个参数，即Test类对象，以后你再调用inc_add，就会触发memoize的__call__函数，同时你传入的参数会被自动拓展为(Test类对象，你传入的参数)，即args[0]是Test类对象，args[1]是你传入的参数
    if obj is None:
      return self.func
    return partial(self, obj)#self是memorize类，而该类声明了__call__函数，因此self本身就可作为函数进行调用，所以符合partial(func, *part_args)的用法，第二个参数是我们将要传进来的类，也就是用于缓存函数结果的类，通过该类的__cache属性来缓存结果,只要这个类没有被free，那么缓存__cache就会一直存在
  def __call__(self, *args, **kw):
    obj = args[0]
    try:
      print(obj)
      print(obj.__cache)
      cache = obj.__cache
    except AttributeError:
      cache = obj.__cache = {}
    key = (self.func, args[1:], frozenset(kw.items()))#这里其实就是使用被装饰的函数、传入的所有参数以及一个frozenset(kw.items())，来作为一个用于唯一标识符，用于对应__cache字典中的value
    try:
      res = cache[key]
      print("HIT")
    except KeyError:
      res = cache[key] = self.func(*args, **kw)
    return res


class Test(object):
  v = 0
  @memoize#注解
  def inc_add(self, arg):
    self.v += 1
    return self.v + arg

t = Test()
print(t)
print(t.inc_add( 2))
t.inc_add
print("ttttt")
print(t.inc_add( 2))
print(t._memoize__cache)
class A(object):
  v=0


a = A()
a.__cache={}
a.__cache

