package sniffer.util;

import java.util.List;

public interface Observable {

    List<Observer> getObservers();

    default void registerObserver(Observer observer) {
        getObservers().add(observer);
    }
}
