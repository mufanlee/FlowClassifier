package weka;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import weka.classifiers.AbstractClassifier;
import weka.classifiers.Classifier;
import weka.classifiers.Evaluation;
import weka.classifiers.trees.J48;
import weka.core.Instances;
import weka.core.OptionHandler;
import weka.core.Utils;
import weka.core.converters.CSVLoader;
import weka.core.converters.ConverterUtils;
import weka.filters.Filter;
import weka.filters.supervised.instance.Resample;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * classify
 *
 * @author lipeng
 * @version 0.2
 */
public class WekaClassifier {
    /**
     * logger
     */
    protected static Logger logger = Logger.getLogger(WekaClassifier.class);

    /**
     * the classifier to use
     */
    protected Classifier classifier = null;

    /**
     * the filter to use
     */
    protected Filter filter = null;

    /**
     * the training file
     */
    protected String trainingFile = null;

    /**
     * the training instances
     */
    protected Instances trainingSet = null;

    /**
     * the training file
     */
    protected String testingFile = null;

    /**
     * the testing instances
     */
    protected Instances testingSet = null;

    /**
     * for evaluating the classifier
     */
    protected Evaluation evaluation = null;

    // construct
    public WekaClassifier() {}

    public WekaClassifier(Classifier classifier, Filter filter, String trainingFile, String testingFile) throws Exception{
        this.classifier = classifier;
        this.filter = filter;
        setTrainingSet(trainingFile);
        setTestingSet(testingFile);
    }

    /**
     * set the classifier to use
     *
     * @param name the classname of the classifier
     * @param options the options for the classifier
     */
    public void setClassifier(String name, String[] options) throws Exception{
        classifier = AbstractClassifier.forName(name, options);
    }

    public void setClassifier(Classifier classifier) {
        this.classifier = classifier;
    }

    /**
     * set the filter to use
     *
     * @param name the classname of the filter
     * @param options the options for the filter
     */
    public void setFilter(String name, String[] options) throws Exception {
        filter = (Filter) Class.forName(name).newInstance();
        if (filter instanceof OptionHandler) {
            filter.setOptions(options);
        }
    }

    public void setFilter(Filter filter, String[] options) throws Exception {
        this.filter = filter;
        if (filter instanceof OptionHandler) {
            filter.setOptions(options);
        }
    }

    /**
     * sets the file to use for training
     */
    public void setTrainingSet(String name) throws Exception {
        trainingFile = name;
        /*String fileType = trainingFile.substring(trainingFile.lastIndexOf("."), trainingFile.length());
        //logger.debug(fileType);
        switch (fileType) {
            case ".csv":
            case ".CSV":
                trainingSet = loadFromCSV(trainingFile);
                break;
            default:    // otherwise, as the .arff
                trainingSet = new Instances(new BufferedReader(new FileReader(trainingFile)));
        }
        trainingSet.setClassIndex(trainingSet.numAttributes() - 1);
        //logger.debug("DataSet\r\n" + trainingSet.toString());*/

        ConverterUtils.DataSource loader = new ConverterUtils.DataSource(trainingFile);
        trainingSet = loader.getDataSet();
        if (trainingSet.classIndex() == -1)
            trainingSet.setClassIndex(trainingSet.numAttributes() - 1);
        //logger.debug("DataSet\r\n" + trainingSet.toString());
    }

    public void setTrainingSet(Instances dataset) {
        trainingSet = dataset;
        if (trainingSet.classIndex() == -1)
            trainingSet.setClassIndex(trainingSet.numAttributes() - 1);
    }

    /**
     * sets the file to use for testing
     */
    public void setTestingSet(String name) throws Exception {
        testingFile = name;
        ConverterUtils.DataSource loader = new ConverterUtils.DataSource(testingFile);
        testingSet = loader.getDataSet();
        if (testingSet.classIndex() == -1)
            testingSet.setClassIndex(testingSet.numAttributes() - 1);
    }

    public void setTestingSet(Instances dataset) {
        testingSet = dataset;
        if (testingSet.classIndex() == -1)
            testingSet.setClassIndex(testingSet.numAttributes() - 1);
    }

    /**
     * load dataset from the .csv file
     */
    public Instances loadFromCSV(String name) throws IOException {
        trainingFile = name;
        CSVLoader loader = new CSVLoader();
        loader.setSource(new File(name));
        loader.setNominalAttributes("2");   //from 1
        //loader.setNumericAttributes("2");
        return loader.getDataSet();
    }

    /**
     * runs 10fold CV over the training file
     */
    public void execute() throws Exception {
        // run filter
        if (filter != null) {
            filter.setInputFormat(trainingSet);
            Instances filtered = Filter.useFilter(trainingSet, filter);

            // train classifier on complete file for tree
            classifier.buildClassifier(filtered);

            // 10fold CV with seed=1
            evaluation = new Evaluation(filtered);
            evaluation.crossValidateModel(classifier, filtered, 10,
                    trainingSet.getRandomNumberGenerator(1));
        } else {
            classifier.buildClassifier(trainingSet);

            evaluation = new Evaluation(trainingSet);
            evaluation.crossValidateModel(classifier, trainingSet, 10,
                    trainingSet.getRandomNumberGenerator(1));
        }
    }

    public Classifier getClassifier() {
        return classifier;
    }

    public Evaluation getEvaluation() {
        return evaluation;
    }


    /**
     * outputs some data about the classifier
     */
    @Override
    public String toString() {
        StringBuffer result = new StringBuffer();
        result.append("Weka - Classify\n===========\n\n");

        result.append("Classifier...: " + Utils.toCommandLine(classifier) + "\n");
        if (filter != null) {
            if (filter instanceof OptionHandler) {
                result.append("Filter.......: " + filter.getClass().getName() + " "
                        + Utils.joinOptions(filter.getOptions()) + "\n");
            } else {
                result.append("Filter.......: " + filter.getClass().getName() + "\n");
            }
        }
        result.append("Training file: " + trainingFile + "\n");
        result.append("\n");

        result.append(classifier.toString() + "\n");
        result.append(evaluation.toSummaryString() + "\n");
        try {
            result.append(evaluation.toMatrixString() + "\n");
        } catch (Exception e) {
            logger.warn("Append evaluation Matrix error: " + e);
        }
        try {
            result.append(evaluation.toClassDetailsString() + "\n");
        } catch (Exception e) {
            logger.warn("Append evaluation ClassDetails error: " + e);
        }

        return result.toString();
    }

    public static void main(String []args) {
        PropertyConfigurator.configure("configs/log4j.properties");

        // 1.Set the dataset
        String dataset = "datasets/features.csv";

        // 2.Set the classifier
        //String classifier = "weka.classifiers.trees.J48";
        Classifier classifier = new J48();
        //List<String> classifierOptions = new ArrayList<>();

        // 3.Set the filter
        //String filter = "";
        //Filter filter = new AllFilter();
        Filter filter = new Resample();
        List<String> filterOptions = new ArrayList<>();
        filterOptions.add("-Z");
        filterOptions.add("100");
        filterOptions.add("-S");
        filterOptions.add("1");
        filterOptions.add("-B");
        filterOptions.add("1");

        WekaClassifier wekaClassifier = new WekaClassifier();
        try {
            //wekaClassifier.setClassifier(classifier, classifierOptions.toArray(new String[classifierOptions.size()]));
            wekaClassifier.setClassifier(classifier);
            wekaClassifier.setFilter(filter, filterOptions.toArray(new String[filterOptions.size()]));
            wekaClassifier.setTrainingSet(dataset);
            wekaClassifier.execute();
            logger.info(wekaClassifier.toString());
        } catch (Exception e) {
            logger.error("Weka execute error: " + e);
        }
    }
}
