#!/bin/bash
BREAK_ON_ERROR=0
VERBOSE=1
VERBOSE_ON_ERROR=0
EVENTS_DIR=/sys/kernel/debug/tracing/events/
TEST_RESULT=./.test_result

files=0
for event in `find $EVENTS_DIR -name format`
do
	files=$((files+1))
	echo -ne "$files"\\r
	$1 $event &> $TEST_RESULT
	if [ $? -ne 0 ]; then
		echo
		echo "Problem in parsing file $event"
		if [ $VERBOSE_ON_ERROR -eq 1 ]; then
			cat $event
			echo
			cat $TEST_RESULT
		fi	
		if [ $BREAK_ON_ERROR -eq 1 ]; then
			exit 1
		fi	
	fi
	if [ $VERBOSE -eq 1 ]; then
		cat $TEST_RESULT
	fi
	rm -rf $TEST_RESULT
done
echo "Checked $files files"