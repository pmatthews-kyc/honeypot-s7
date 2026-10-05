PROGRAM tank_sequencer
VAR
    seq_state   : INT := 0;
    pump_run    : BOOL;
    valve_open  : BOOL;
    flow_ok     : BOOL;
    temp        : INT := 250;
    flow_rate   : INT := 0;
    pressure    : INT := 300;
    lvl         : INT := 900;
    setpoint    : INT := 300;
    temp_hi     : BOOL;
    temp_lo     : BOOL;
    heater_on   : BOOL;
    lvl_presc   : INT := 0;
    scan_ctr    : INT := 0;

    t_start     : TON;
    t_alarm     : TON;
END_VAR

VAR
    out_temp  AT %QW0  : INT;
    out_flow  AT %QW1  : INT;
    out_pres  AT %QW2  : INT;
    out_lvl   AT %QW3  : INT;
    out_setpt AT %QW4  : INT;
    out_seq   AT %QW5  : INT;
    out_scan  AT %QW6  : INT;
    out_pump  AT %QX0.0 : BOOL;
    out_valve AT %QX0.1 : BOOL;
    out_thi   AT %QX0.2 : BOOL;
    out_tlo   AT %QX0.3 : BOOL;
END_VAR

(* ---- Step sequencer ---- *)

CASE seq_state OF
    0: (* IDLE - refill the tank, then start the next batch.
          The 5s timer alone is not enough: after a low-level stop the
          tank sits at ~10%, so starting on the timer alone re-trips the
          low-level condition within seconds and the sequencer thrashes.
          A real batch process waits for the tank to refill first. *)
       pump_run   := FALSE;
       valve_open := FALSE;
       t_start(IN := TRUE, PT := T#5S);
       IF t_start.Q AND lvl >= 800 THEN
           t_start(IN := FALSE);
           seq_state := 1;
       END_IF;

    1: (* STARTING *)
       valve_open := TRUE;
       pump_run   := TRUE;
       flow_ok    := flow_rate > 50;
       IF flow_ok THEN seq_state := 2; END_IF;

    2: (* RUNNING *)
       IF temp_hi THEN
           seq_state := 4;
       ELSIF lvl < 100 THEN
           seq_state := 3;
       END_IF;

    3: (* STOPPING *)
       pump_run   := FALSE;
       valve_open := FALSE;
       IF flow_rate < 5 THEN seq_state := 0; END_IF;

    4: (* ALARM - hold 30s *)
       pump_run := FALSE;
       t_alarm(IN := TRUE, PT := T#30S);
       IF t_alarm.Q AND NOT temp_hi THEN
           t_alarm(IN := FALSE);
           seq_state := 0;
       END_IF;

    ELSE seq_state := 0;

END_CASE;


(* ---- Process physics ---- *)

IF pump_run THEN
    (* Heater hysteresis control, +/- 0.5 degC around setpoint.
       The previous version heated open-loop up to setpoint+50 (35.0C)
       while the alarm trips at setpoint+30 (33.0C) - the cap was ABOVE
       the trip point, so every run cycle alarmed. Real control stops
       heating at the setpoint. *)
    IF temp <= setpoint - 5 THEN
        heater_on := TRUE;
    ELSIF temp >= setpoint + 5 THEN
        heater_on := FALSE;
    END_IF;
ELSE
    heater_on := FALSE;
END_IF;

IF heater_on THEN
    IF temp < 900 THEN temp := temp + 1; END_IF;
ELSE
    IF temp > 200 THEN temp := temp - 1; END_IF;
END_IF;

IF pump_run AND valve_open THEN
    IF flow_rate < 1200 THEN flow_rate := flow_rate + 3; END_IF;
ELSE
    IF flow_rate > 0 THEN
        flow_rate := flow_rate - 5;
        IF flow_rate < 0 THEN flow_rate := 0; END_IF;
    END_IF;
END_IF;

IF pump_run THEN
    IF pressure < 620 THEN pressure := pressure + 2; END_IF;
ELSE
    IF pressure > 310 THEN pressure := pressure - 1; END_IF;
END_IF;

(* Level prescaler: at a 20ms scan a raw +/-1 per cycle drains the tank
   90% -> 10% in ~16 seconds, giving a full batch every 20s. No real tank
   behaves that way, and it floods the 100-entry diagnostic buffer with
   repetitive pump cycling in minutes. Adjusting level once per 40 scans
   (800ms) stretches a batch to roughly 10 minutes, which is realistic for
   a fill/drain process and keeps hours of history in the buffer. *)
lvl_presc := lvl_presc + 1;
IF lvl_presc >= 40 THEN
    lvl_presc := 0;
    IF pump_run THEN
        IF lvl > 0 THEN lvl := lvl - 1; END_IF;
    ELSE
        (* Refill at 3x the drain rate: draining is the productive part of
           the batch, refilling is changeover. Gives ~10min run + ~4min
           fill = a ~14 minute cycle. *)
        IF lvl < 900 THEN lvl := lvl + 3; END_IF;
        IF lvl > 900 THEN lvl := 900; END_IF;
    END_IF;
END_IF;


(* ---- Alarms ---- *)

temp_hi := temp > (setpoint + 30);
temp_lo := temp < 250;


(* ---- Scan counter ---- *)

scan_ctr := scan_ctr + 1;
IF scan_ctr > 32767 THEN scan_ctr := 0; END_IF;


(* ---- Copy to output variables (Modbus mapped) ---- *)

out_temp  := temp;
out_flow  := flow_rate;
out_pres  := pressure;
out_lvl   := lvl;
out_setpt := setpoint;
out_seq   := seq_state;
out_scan  := scan_ctr;
out_pump  := pump_run;
out_valve := valve_open;
out_thi   := temp_hi;
out_tlo   := temp_lo;

END_PROGRAM


CONFIGURATION Config0

    RESOURCE Res0 ON PLC
        TASK task0 (INTERVAL := T#20ms, PRIORITY := 0);
        PROGRAM instance0 WITH task0 : tank_sequencer;
    END_RESOURCE

END_CONFIGURATION