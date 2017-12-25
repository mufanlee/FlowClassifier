package weka;

import org.apache.log4j.PropertyConfigurator;
import util.FileUtility;
import weka.attributeSelection.CfsSubsetEval;
import weka.attributeSelection.GreedyStepwise;
import weka.classifiers.Evaluation;
import weka.classifiers.trees.J48;
import weka.core.Instances;
import weka.core.SerializationHelper;
import weka.filters.Filter;
import weka.filters.MultiFilter;
import weka.filters.supervised.attribute.AttributeSelection;
import weka.filters.supervised.instance.Resample;
import weka.filters.unsupervised.attribute.Normalize;
import weka.filters.unsupervised.instance.Randomize;
import weka.filters.unsupervised.instance.RemoveDuplicates;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

public class QoSClassifier extends WekaClassifier {
    @Override
    public void execute() throws Exception {
        String dataset = "datasets/201701.arff";
        setTrainingSet(dataset);
        //setTestingSet("datasets/100kbfeatures10.arff");

        /*
        // 采样
        Resample resample = new Resample();
        resample.setBiasToUniformClass(1);
        resample.setRandomSeed(1);
        resample.setSampleSizePercent(25);
        resample.setNoReplacement(true);
        //resample.setInputFormat(trainingSet);
        //Instances sampleData = Filter.useFilter(trainingSet, filter);

        // 去重
        RemoveDuplicates removeDuplicates = new RemoveDuplicates();

        // 特征选择
        AttributeSelection selection = new AttributeSelection();
        CfsSubsetEval eval = new CfsSubsetEval();
        GreedyStepwise search = new GreedyStepwise();
        search.setSearchBackwards(true);
        selection.setEvaluator(eval);
        selection.setSearch(search);
        //selection.setInputFormat(trainingSet);
        //Instances selecteData = Filter.useFilter(sampleData, selection);

        // 规范化
        Normalize normalize = new Normalize();
        normalize.setScale(1);
        normalize.setTranslation(0);
        //normalize.setInputFormat(trainingSet);
        //Instances newData = Filter.useFilter(selecteData, normalize);

        // 随机重排
        Randomize randomize = new Randomize();
        randomize.setRandomSeed(42);

        //Filter []filters = {removeDuplicates, selection, resample, normalize, randomize};
        Filter[]filters = {removeDuplicates, resample, normalize, randomize};
        MultiFilter multiFilter = new MultiFilter();
        multiFilter.setFilters(filters);
        filter = multiFilter;
        filter.setInputFormat(trainingSet);
        Instances newTrain = Filter.useFilter(trainingSet, filter);

        //Instances newTest = Filter.useFilter(testingSet, filter);

        logger.info(newTrain.toSummaryString());*/
        //logger.info(newTest.toSummaryString());

        /*for (int i = 0; i < 20; i++) {
            System.out.println(newDataSet.instance(i));
        }*/

        // C4.5决策树
        J48 j48 = new J48();
        //j48.setMinNumObj(100);
        classifier = j48;

        // k近邻
        //IBk iBk= new IBk();
        //iBk.setKNN(50);
        //classifier = iBk;

        // 贝叶斯
        //classifier = new NaiveBayes();
        //classifier = new BayesNet();
        //classifier = new NaiveBayesMultinomial();

        // 支持向量机
        //classifier = new SMO();

        // AdaBoost M1
        //classifier = new AdaBoostM1();

        // 神经网络
        //classifier = new MultilayerPerceptron();

        // 随机森林
        //classifier = new RandomForest();

        classifier.buildClassifier(trainingSet);

        SerializationHelper.write("models/QoSClassifier.model", classifier);

        // 10fold CV with seed = 1
        evaluation = new Evaluation(trainingSet);
        evaluation.crossValidateModel(classifier, trainingSet, 10,
                trainingSet.getRandomNumberGenerator(1));

        /*classifier.buildClassifier(newTrain);
        // 在测试集上评估
        evaluation = new Evaluation(newTrain);
        evaluation.evaluateModel(classifier, newTest);*/

        logger.info(toString());
        FileUtility.writeFile(toString(), "datasets/" + classifier.getClass().getSimpleName() + ".txt", true);
    }

    public static void main(String []args) {
        PropertyConfigurator.configure("configs/log4j.properties");
        try {
            QoSClassifier classifier = new QoSClassifier();
            classifier.execute();
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Weka execute error: " + e);
        }
    }
}
