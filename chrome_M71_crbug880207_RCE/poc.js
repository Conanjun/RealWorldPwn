
// d8 --allow-natives-syntax poc.js


function foo() {
  return Object.is(Math.expm1(-0), -0);
}

console.log(foo());
%OptimizeFunctionOnNextCall(foo);
console.log(foo());