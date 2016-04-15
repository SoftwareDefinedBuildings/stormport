SERP: Saint-Exupery Routing Protocol
==============================

```
Il semble que la perfection soit atteinte non quand il n'y a plus rien à
ajouter, mais quand il n'y a plus rien à retrancher.

It seems that perfection is attained not when there is nothing more to add, but
when there is nothing more to remove
```

## Implementation Plan

* [ ] need a trigger when a packet fails to send -- need to rebuilt routing
* [ ] need to build up alternative routing tables when we hear neighbors in another message

## Trickle Timer

How do we define/use trickle timers?

```nesc
uses {
    interface Timer<TMilli> as TrickleTimer;
}

uint32_t tricklePeriod = 0;
bool fired = FALSE;

void resetTrickleTimer() {
    call TrickleTimer.stop();
    tricklePeriod = 2 << (intervalMin - 1);
    redundancyCounter = 0;
    doubleCounter = 0;
}

void chooseTrickleTime() {
    call TrickleTimer.stop();
    randomTime = tricklePeriod;
    randomTime /= 2;
    randomTime += call Random.rand32() % randomTime;
    call TrickleTimer.startOneShot(randomTime);
}

void computeTrickleRemaining() {
    uint32_t remain = tricklePeriod - randomTime;
    fired = TRUE;
    call TrickleTimer.startOneShot(remain);
}

void nextTrickleTime() {
    fired = FALSE;
    if (doubleCounter < intervalMin) {
        doubleCounter++;
        tricklePeriod *= 2;
    }
    if (!call TrickleTimer.isRunning()) {
        chooseTrickleTime();
    }
}

event void TrickleTimer.fired() {
    if (fired) {
        nextTrickleTime();
    } else {
        // send packet here
        post computeTrickleRemaining();
    }
}
```
