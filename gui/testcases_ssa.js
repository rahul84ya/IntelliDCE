// Pre-computed GIMPLE SSA representations for TC01-TC17 and sample files
// Compatible with IntelliDCE GIMPLE SSA parser
const TESTCASES_SSA = {
  TC01: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int x;
  int y;
  int _5;

  <bb 2> :
  x_1 = 5;
  y_2 = x_1 + 2;
  std::basic_ostream<char>::operator<< (&cout, x_1);
  _5 = 0;

  <bb 3> :
<L0>:
  return _5;

}
`,
  TC02: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int x;
  int _5;

  <bb 2> :
  if (0 != 0)
    goto <bb 3>; [INV]
  else
    goto <bb 4>; [INV]

  <bb 3> :
  x_1 = 5;

  <bb 4> :
  std::operator<< <std::char_traits<char> > (&cout, "Done");
  _5 = 0;

  <bb 5> :
<L0>:
  return _5;

}
`,
  TC03: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int a;
  int b;
  int c;
  int _5;

  <bb 2> :
  a_1 = 2;
  b_2 = a_1 + 3;
  c_3 = b_2 * 4;
  std::basic_ostream<char>::operator<< (&cout, a_1);
  _5 = 0;

  <bb 3> :
<L0>:
  return _5;

}
`,
  TC04: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int a;
  int b;
  int c;
  int _5;

  <bb 2> :
  a_1 = 3;
  b_2 = a_1 + 2;
  c_3 = b_2 * 2;
  std::basic_ostream<char>::operator<< (&cout, b_2);
  _5 = 0;

  <bb 3> :
<L0>:
  return _5;

}
`,
  TC05: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int sum;
  int i;
  int temp;
  int _8;

  <bb 2> :
  sum_1 = 0;
  i_2 = 0;
  goto <bb 4>; [INV]

  <bb 3> :
  temp_4 = i_3 * 3;
  sum_5 = sum_7 + i_3;
  i_6 = i_3 + 1;

  <bb 4> :
  # sum_7 = PHI <sum_1(2), sum_5(3)>
  # i_3 = PHI <i_2(2), i_6(3)>
  if (i_3 <= 4)
    goto <bb 3>; [INV]
  else
    goto <bb 5>; [INV]

  <bb 5> :
  std::basic_ostream<char>::operator<< (&cout, sum_7);
  _8 = 0;

  <bb 6> :
<L0>:
  return _8;

}
`,
  TC06: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int x;
  int y;
  int _5;

  <bb 2> :
  x_1 = 10;
  std::operator<< <std::char_traits<char> > (&cout, "Hello");
  y_2 = x_1 + 5;
  _5 = 0;

  <bb 3> :
<L0>:
  return _5;

}
`,
  TC07: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int a;
  int * p;
  int _5;

  <bb 2> :
  a_1 = 5;
  p_2 = &a_1;
  *p_2 = 20;
  _5 = 0;

  <bb 3> :
<L0>:
  return _5;

}
`,
  TC08: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int x;
  int _5;

  <bb 2> :
  x_1 = 0;
  if (x_1 != 0)
    goto <bb 3>; [INV]
  else
    goto <bb 4>; [INV]

  <bb 3> :
  std::operator<< <std::char_traits<char> > (&cout, "A");
  goto <bb 5>; [INV]

  <bb 4> :
  std::operator<< <std::char_traits<char> > (&cout, "B");

  <bb 5> :
  _5 = 0;

  <bb 6> :
<L0>:
  return _5;

}
`,
  TC09: `
;; Function f (_Z1fv, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

void f ()
{
  <bb 2> :
  std::operator<< <std::char_traits<char> > (&cout, "Side");
  return;

}

;; Function main (main, funcdef_no=1, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int x;
  int _5;

  <bb 2> :
  f ();
  x_1 = 5;
  _5 = 0;

  <bb 3> :
<L0>:
  return _5;

}
`,
  TC10: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int a;
  int b;
  int c;
  int _5;

  <bb 2> :
  a_1 = 4;
  b_2 = a_1 + 3;
  c_3 = b_2 + 2;
  std::basic_ostream<char>::operator<< (&cout, a_1);
  _5 = 0;

  <bb 3> :
<L0>:
  return _5;

}
`,
  TC11: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int x;
  int _5;

  <bb 2> :
  if (1 != 0)
    goto <bb 3>; [INV]
  else
    goto <bb 6>; [INV]

  <bb 3> :
  if (0 != 0)
    goto <bb 4>; [INV]
  else
    goto <bb 5>; [INV]

  <bb 4> :
  x_1 = 5;

  <bb 5> :
  <bb 6> :
  _5 = 0;

  <bb 7> :
<L0>:
  return _5;

}
`,
  TC12: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int a;
  int b;
  int c;
  int d;
  int _5;

  <bb 2> :
  a_1 = 1;
  b_2 = 2;
  c_3 = a_1 + b_2;
  d_4 = c_3 + 5;
  std::basic_ostream<char>::operator<< (&cout, a_1);
  _5 = 0;

  <bb 3> :
<L0>:
  return _5;

}
`,
  TC13: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int sum;
  int i;
  int x;
  int y;
  int _8;

  <bb 2> :
  sum_1 = 0;
  i_2 = 0;
  goto <bb 4>; [INV]

  <bb 3> :
  x_4 = i_3 * 2;
  sum_5 = sum_7 + i_3;
  y_6 = i_3 + 10;
  i_8 = i_3 + 1;

  <bb 4> :
  # sum_7 = PHI <sum_1(2), sum_5(3)>
  # i_3 = PHI <i_2(2), i_8(3)>
  if (i_3 <= 4)
    goto <bb 3>; [INV]
  else
    goto <bb 5>; [INV]

  <bb 5> :
  std::basic_ostream<char>::operator<< (&cout, sum_7);
  _8 = 0;

  <bb 6> :
<L0>:
  return _8;

}
`,
  TC14: `
;; Function f (_Z1fi, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int f (int x)
{
  int _2;

  <bb 2> :
  _2 = x_1(D) * 2;

  <bb 3> :
<L0>:
  return _2;

}

;; Function main (main, funcdef_no=1, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int val;
  int _5;

  <bb 2> :
  val_1 = f (5);
  _5 = 0;

  <bb 3> :
<L0>:
  return _5;

}
`,
  TC15: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int x;
  int y;
  int _5;

  <bb 2> :
  x_1 = 5;
  _5 = 0;
  return _5;
  y_2 = x_1 + 2;

}
`,
  TC16: `
;; Function f (_Z1fi, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int f (int n)
{
  int _3;

  <bb 2> :
  if (n_1(D) == 0)
    goto <bb 3>; [INV]
  else
    goto <bb 4>; [INV]

  <bb 3> :
  _3 = 0;
  goto <bb 5>; [INV]

  <bb 4> :
  _2 = n_1(D) + -1;
  _3 = f (_2);

  <bb 5> :
  return _3;

}

;; Function main (main, funcdef_no=1, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int _5;

  <bb 2> :
  f (3);
  _5 = 0;

  <bb 3> :
<L0>:
  return _5;

}
`,
  TC17: `
;; Function main (main, funcdef_no=0, decl_uid=0, cgraph_uid=0, symbol_order=0)

int main ()
{
  int a;
  int b;
  int c;
  int _5;

  <bb 2> :
  a_1 = 5;
  b_2 = a_1 + 2;
  if (0 != 0)
    goto <bb 3>; [INV]
  else
    goto <bb 4>; [INV]

  <bb 3> :
  c_3 = b_2 * 2;

  <bb 4> :
  std::basic_ostream<char>::operator<< (&cout, a_1);
  _5 = 0;

  <bb 5> :
<L0>:
  return _5;

}
`
};

module.exports = { TESTCASES_SSA };
