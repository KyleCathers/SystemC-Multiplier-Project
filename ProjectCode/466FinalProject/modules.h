#include "systemc.h"
#include "digit.h"

SC_MODULE(half_mult) {
	sc_in<NN_HALF_DIGIT> in_data_1;
	sc_in<NN_HALF_DIGIT> in_data_2;
	sc_out<NN_DIGIT> out_data;


	void process_half_mult() {
		out_data.write((NN_DIGIT)(in_data_1.read()) * (NN_DIGIT)(in_data_2.read()));
	}

	SC_CTOR(half_mult) {
		SC_METHOD(process_half_mult);
		sensitive << in_data_1 << in_data_2;
	}
};


SC_MODULE(splitter) {
	sc_in<NN_DIGIT> in_data;
	sc_out<NN_HALF_DIGIT> out_data_low;
	sc_out<NN_HALF_DIGIT> out_data_high;


	void process_splitter() {
		out_data_low.write((NN_HALF_DIGIT)LOW_HALF(in_data.read()));
		out_data_high.write((NN_HALF_DIGIT)HIGH_HALF(in_data.read()));
	}

	SC_CTOR(splitter) {
		SC_METHOD(process_splitter);
		sensitive << in_data;
	}
};


SC_MODULE(adder) {
	sc_in<NN_DIGIT> in_data_1;
	sc_in<NN_DIGIT> in_data_2;
	sc_out<NN_DIGIT> out_data;


	void process_adder() {
		out_data.write(in_data_1.read() + in_data_2.read());
	}

	SC_CTOR(adder) {
		SC_METHOD(process_adder);
		sensitive << in_data_1 << in_data_2;
	}
};


SC_MODULE(to_high_half) {
	sc_in<NN_DIGIT> in_data;
	sc_out<NN_DIGIT> out_data;


	void process_to_hh() {
		out_data.write((NN_DIGIT)(TO_HIGH_HALF(in_data.read())));
	}

	SC_CTOR(to_high_half) {
		SC_METHOD(process_to_hh);
		sensitive << in_data;
	}
};

SC_MODULE(high_half) {
	sc_in<NN_DIGIT> in_data;
	sc_out<NN_DIGIT> out_data;

	void process_hh() {
		out_data.write((NN_DIGIT)HIGH_HALF(in_data.read()));
	}

	SC_CTOR(high_half) {
		SC_METHOD(process_hh);
		sensitive << in_data;
	}
};

SC_MODULE(MUX) {
	sc_in<NN_DIGIT> in_data1;
	sc_in<NN_DIGIT> in_data2;
	sc_in<bool> select;
	sc_out<NN_DIGIT> out_data;

	void process_MUX() {
		if (select) {			// select = 1
			out_data.write(in_data1.read());
		} else {				// select = 0
			out_data.write(in_data2.read());
		}
	}

	SC_CTOR(MUX) {
		SC_METHOD(process_MUX);
		sensitive << in_data1 << in_data2 << select;
	}
};

SC_MODULE(comparator) {
	sc_in<NN_DIGIT> in_data1;
	sc_in<NN_DIGIT> in_data2;
	sc_out<bool> en;

	void process_comparator() {
		if (in_data1.read() < in_data2.read()) {
			en.write(1);
		} else {
			en.write(0);
		}
	}

	SC_CTOR(comparator) {
		SC_METHOD(process_comparator);
		sensitive << in_data1 << in_data2;
	}
};