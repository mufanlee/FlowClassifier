package pcapparser.util;

import java.io.Serializable;
import java.util.Date;


/**
 * POSIX.4 timeval for Java.
 * <p>
 * Container for java equivalent of c's struct timeval.
 *
 * @author lipeng
 * @version 1.0
 */
public class Timeval implements Serializable
{
    public Timeval(long seconds, int microseconds) {
        this.seconds = seconds;
        this.microseconds = microseconds;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(seconds);
        sb.append('.');
        sb.append(microseconds);
        sb.append('s');

        return sb.toString();
    }

    /**
     * Convert this timeval to a java Date.
     */
    public Date getDate() {
        return new Date(seconds * 1000 + microseconds / 1000);
    }

    public long getSeconds() {
        return seconds;
    }

    public int getMicroSeconds() {
        return microseconds;
    }

    long seconds;
    int microseconds;
}
