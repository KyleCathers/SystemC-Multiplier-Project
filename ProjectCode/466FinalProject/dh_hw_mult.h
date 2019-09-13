#include "systemc.h"
#include "digit.h"

#ifndef _DH_HW_MULT_H_
#define _DH_HW_MULT_H_ 1

SC_MODULE(dh_hw_mult) {
	sc_in_clk clk;

	// SW ports
	sc_in<bool> hw_mult_enable;
	sc_in<NN_DIGIT> in_data_1;
	sc_in<NN_DIGIT> in_data_2;
	sc_out<NN_DIGIT> out_data_low;
	sc_out<NN_DIGIT> out_data_high;
	sc_out<bool> hw_mult_done;

	// HW multiplication ports
	sc_out<NN_DIGIT> b_out;
	sc_out<NN_DIGIT> c_out;

	sc_in<NN_DIGIT> a0;
	sc_in<NN_DIGIT>	a1;

	void process_hw_mult() {
		NN_DIGIT a[2], b, c;

		// states for handshaking
		enum ctrl_state { WAIT, EXECUTE, OUTPUT, FINISH };
		ctrl_state state = WAIT;

		hw_mult_done.write(false);

		while (1) {
			switch (state) {
			case WAIT:		// wait for enable signal to be asserted
				if (hw_mult_enable.read() == true) {
					state = EXECUTE;
				}
				break;

			case EXECUTE:	// multiply two inputs
				// Read inputs	
				b = in_data_1.read();
				c = in_data_2.read();

				// send data out to be multiplied
				b_out.write(b);
				c_out.write(c);
				wait();

				// receive multiplied results
				a[0] = a0.read();
				a[1] = a1.read();		

				state = OUTPUT;
				break;

			case OUTPUT:	// write to output ports of module, assert done signal 
				hw_mult_done.write(true);
				out_data_low.write(a[0]);
				out_data_high.write(a[1]);
				state = FINISH;
				break;

			case FINISH:	// check if enable is deasserted; if so, deassert done
				if (hw_mult_enable.read() == false) {
					hw_mult_done.write(false);
					state = WAIT;
				}
				break;
			}
			wait();
		}
	};

	SC_CTOR(dh_hw_mult) {
		SC_CTHREAD(process_hw_mult, clk.pos());
	}
};
#endif /* end _DH_HW_MULT_H_ */

/*
//Original code from NN_DigitMult()...
bHigh = (NN_HALF_DIGIT)HIGH_HALF(b);
bLow = (NN_HALF_DIGIT)LOW_HALF(b);
cHigh = (NN_HALF_DIGIT)HIGH_HALF(c);
cLow = (NN_HALF_DIGIT)LOW_HALF(c);

a[0] = (NN_DIGIT)bLow * (NN_DIGIT)cLow;
t = (NN_DIGIT)bLow * (NN_DIGIT)cHigh;
u = (NN_DIGIT)bHigh * (NN_DIGIT)cLow;
a[1] = (NN_DIGIT)bHigh * (NN_DIGIT)cHigh;

t = t + u;

if (t < u) {
	a[1] = a[1] + TO_HIGH_HALF(1);
}
u = TO_HIGH_HALF(t);

a[0] = a[0] + u;

if (a[0] < u) {
	a[1] = a[1] + 1;
}
a[1] = a[1] + HIGH_HALF(t);
//	end of original code from NN_DigitMult()...
*/