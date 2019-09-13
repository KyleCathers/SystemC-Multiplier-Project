#include "systemc.h"
#include "digit.h"
#include "dh_sw.h"
#include "dh_hw_mult.h"
#include "modules.h"

int sc_main(int argc , char *argv[])
{
	sc_signal <bool> enable, done;
	sc_signal <NN_DIGIT> operand1, operand2, result1, result2, nn_1;
	sc_clock hw_clk("HW_Clock", 10, SC_NS, 0.5, 1, SC_NS);

	// initialization
	enable.write(false);
	done.write(false);
	nn_1.write(1);

	// dh_hw_mult output signals
	sc_signal <NN_DIGIT> b_out_s, c_out_s;
	// splitter output signals
	sc_signal <NN_HALF_DIGIT> b_low_s, b_high_s, c_low_s, c_high_s;
	// halfmult output signals
	sc_signal <NN_DIGIT> a0_1_s, t1_s, u1_s, a1_1_s;
	// adder output signals (adder 1, adder 2, adder 3, adder 4, adder 5)
	sc_signal <NN_DIGIT> t2_s, adder2_out_s, adder3_out_s, a0_2_s, a1_4_s;
	// comparator output signals
	sc_signal <bool> select1, select2;
	// MUX output signals
	sc_signal <NN_DIGIT> a1_2_s, a1_3_s;
	// to_high_half output signals
	sc_signal <NN_DIGIT> thh_1_s, u2_s;
	// high_half output signals
	sc_signal <NN_DIGIT> hh_s;

	dh_sw DH_SW("DH_Software");
	DH_SW.out_data_1 (operand1);		// operand1 to hardware
	DH_SW.out_data_2 (operand2);		// operand2 to hardware
	DH_SW.in_data_low (result1);		// result1 from hardware
	DH_SW.in_data_high (result2);		// result2 from hardware
	DH_SW.hw_mult_enable (enable);		// enable hardware
	DH_SW.hw_mult_done (done);			// hardware done
	
	dh_hw_mult DH_HW_MULT("DH_Hardware_Multiplier");
	DH_HW_MULT.clk(hw_clk);
	DH_HW_MULT.in_data_1 (operand1);	// operand1 from software
	DH_HW_MULT.in_data_2 (operand2);	// operand2 from software
	DH_HW_MULT.out_data_low (result1);	// result1 to software
	DH_HW_MULT.out_data_high (result2);	// result2 to software
	DH_HW_MULT.hw_mult_enable (enable);	// enable hardware
	DH_HW_MULT.hw_mult_done (done);		// hardware done
	DH_HW_MULT.b_out(b_out_s);			// output b to multiplier components
	DH_HW_MULT.c_out(c_out_s);			// output c to multiplier components
	DH_HW_MULT.a0(a0_2_s);				// input a_low from multiplier components
	DH_HW_MULT.a1(a1_4_s);				// input a_high from multiplier components

	// splitters
	splitter splitter1("Splitter1");
	splitter1.in_data(b_out_s);
	splitter1.out_data_low(b_low_s);	// bLow = (NN_HALF_DIGIT)LOW_HALF(b);
	splitter1.out_data_high(b_high_s);	// bHigh = (NN_HALF_DIGIT)HIGH_HALF(b);

	splitter splitter2("Splitter2");
	splitter2.in_data(c_out_s);
	splitter2.out_data_low(c_low_s);	// cLow = (NN_HALF_DIGIT)LOW_HALF(c);
	splitter2.out_data_high(c_high_s);	// cHigh = (NN_HALF_DIGIT)HIGH_HALF(c);

	// half digit muiltipliers
	half_mult mult1("mult1");
	mult1.in_data_1(b_low_s);
	mult1.in_data_2(c_low_s);
	mult1.out_data(a0_1_s);				// a[0] = (NN_DIGIT)bLow * (NN_DIGIT)cLow;

	half_mult mult2("mult2");
	mult2.in_data_1(b_low_s);
	mult2.in_data_2(c_high_s);
	mult2.out_data(t1_s);				// t = (NN_DIGIT)bLow * (NN_DIGIT)cHigh;

	half_mult mult3("mult3");
	mult3.in_data_1(b_high_s);
	mult3.in_data_2(c_low_s);
	mult3.out_data(u1_s);				// u = (NN_DIGIT)bHigh * (NN_DIGIT)cLow;

	half_mult mult4("mult41");
	mult4.in_data_1(b_high_s);
	mult4.in_data_2(c_high_s);
	mult4.out_data(a1_1_s);				// a[1] = (NN_DIGIT)bHigh * (NN_DIGIT)cHigh;

	// adders
	adder adder1("adder1");
	adder1.in_data_1(t1_s);
	adder1.in_data_2(u1_s);
	adder1.out_data(t2_s);				// t + u

	adder adder2("adder2");
	adder2.in_data_1(thh_1_s);
	adder2.in_data_2(a1_1_s);
	adder2.out_data(adder2_out_s);		// a[1] = a[1] + TO_HIGH_HALF(1);

	adder adder3("adder3");
	adder3.in_data_1(nn_1);
	adder3.in_data_2(a1_2_s);
	adder3.out_data(adder3_out_s);		// a[1] = a[1] + 1;

	adder adder4("adder4");
	adder4.in_data_1(a0_1_s);
	adder4.in_data_2(u2_s);
	adder4.out_data(a0_2_s);			// a[0] + u

	adder adder5("adder5");
	adder5.in_data_1(a1_3_s);
	adder5.in_data_2(hh_s);
	adder5.out_data(a1_4_s);			// a[1] = a[1] + HIGH_HALF(t);

	// MUXes (for if statements)
	MUX mux1("MUX1");
	mux1.in_data1(adder2_out_s);		// a[1] = a[1] + TO_HIGH_HALF(1)
	mux1.in_data2(a1_1_s);				// a[1]
	mux1.select(select1);
	mux1.out_data(a1_2_s);				// if (t < u) ...

	MUX mux2("MUX2");
	mux2.in_data1(adder3_out_s);		// a[1] = a[1] + 1
	mux2.in_data2(a1_2_s);				// a[1]
	mux2.select(select2);
	mux2.out_data(a1_3_s);				// if ((a[0] + u) < u) ...

	// comparators
	comparator comparator1("comparator1");
	comparator1.in_data1(t2_s);			// t
	comparator1.in_data2(u1_s);			// u
	comparator1.en(select1);			// ((t + u) < u)

	comparator comparator2("comparator2");
	comparator2.in_data1(a0_2_s);		// a[0]
	comparator2.in_data2(u2_s);			// u
	comparator2.en(select2);			// ((a[0] + u) < u)

	// high half component
	high_half high_half1("high_half1");
	high_half1.in_data(t2_s);
	high_half1.out_data(hh_s);			// HIGH_HALF(t);

	// to high half components
	to_high_half to_high_half1("to_high_half1");
	to_high_half1.in_data(nn_1);
	to_high_half1.out_data(thh_1_s);	// TO_HIGH_HALF(1)

	to_high_half to_high_half2("to_high_half2");
	to_high_half2.in_data(t2_s);
	to_high_half2.out_data(u2_s);		// u = TO_HIGH_HALF(t);

	sc_start();

	return(0);
}
