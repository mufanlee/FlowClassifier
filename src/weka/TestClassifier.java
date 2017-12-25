package weka;

import org.apache.log4j.PropertyConfigurator;
import weka.classifiers.evaluation.ThresholdCurve;
import weka.filters.supervised.attribute.AttributeSelection;
import weka.attributeSelection.CfsSubsetEval;
import weka.attributeSelection.GreedyStepwise;
import weka.classifiers.Evaluation;
import weka.classifiers.trees.J48;
import weka.core.Instances;
import weka.filters.Filter;
import weka.filters.supervised.instance.Resample;

import weka.core.Utils;
import weka.gui.visualize.PlotData2D;
import weka.gui.visualize.ThresholdVisualizePanel;

import java.awt.*;

public class TestClassifier extends WekaClassifier{

    @Override
    public void execute() throws Exception {
        String dataset = "datasets/features.arff";
        setTrainingSet(dataset);

        // 采样
        Resample resample = new Resample();
        resample.setBiasToUniformClass(1);
        resample.setRandomSeed(1);
        resample.setSampleSizePercent(10);
        filter = resample;
        filter.setInputFormat(trainingSet);
        Instances filtered = Filter.useFilter(trainingSet, filter);

        // 特征选择
        AttributeSelection sfl = new AttributeSelection();
        CfsSubsetEval eval = new CfsSubsetEval();
        GreedyStepwise search = new GreedyStepwise();
        search.setSearchBackwards(true);
        sfl.setEvaluator(eval);
        sfl.setSearch(search);
        sfl.setInputFormat(filtered);
        Instances newData = Filter.useFilter(filtered, sfl);
        filter = sfl;

        classifier = new J48();
        // train classifier on complete file for tree
        classifier.buildClassifier(newData);

        // 10fold CV with seed=1
        evaluation = new Evaluation(newData);
        evaluation.crossValidateModel(classifier, newData, 10,
                trainingSet.getRandomNumberGenerator(1));

        // 在测试集上评估
        //evaluation.evaluateModel(classifier, newData);

        // ROC曲线
        // 生成用于得到ROC曲面和AUC值的Instances对象
        ThresholdCurve tc = new ThresholdCurve();
        int classIndex = 0;
        Instances result = tc.getCurve(evaluation.predictions(), classIndex);
        System.out.println("ROC曲线下的面积：" + evaluation.areaUnderPRC(classIndex));

        /*
         * 在这里我们通过结果信息Instances对象得到包含TP、FP的两个数组
         * 这两个数组用于在SPSS中通过线图绘制ROC曲面
         */
        int tpIndex = result.attribute(ThresholdCurve.TP_RATE_NAME).index();
        int fpIndex = result.attribute(ThresholdCurve.FP_RATE_NAME).index();
        double [] tpRate = result.attributeToDoubleArray(tpIndex);
        double [] fpRate = result.attributeToDoubleArray(fpIndex);
        //Utils.writeArray(tpRate, fpRate, "d:\roc.txt");

        // 使用结果信息instances对象来显示ROC曲面
        ThresholdVisualizePanel vmc = new ThresholdVisualizePanel();

        //这个获得AUC的方式与上面的不同，其实得到的都是一个共同的结果
        vmc.setROCString("(Area under ROC = " +
                Utils.doubleToString(tc.getROCArea(result), 4) + ")");
        vmc.setName(result.relationName());
        PlotData2D tempd = new PlotData2D(result);
        tempd.setPlotName(result.relationName());
        tempd.addInstanceNumberAttribute();
        vmc.addPlot(tempd);

        // 显示曲面
        String plotName = vmc.getName();
        final javax.swing.JFrame jf =
                new javax.swing.JFrame("Weka Classifier Visualize: "+plotName);
        jf.setSize(500,400);
        jf.getContentPane().setLayout(new BorderLayout());
        jf.getContentPane().add(vmc, BorderLayout.CENTER);
        jf.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent e) {
                jf.dispose();
            }
        });
        jf.setVisible(true);
    }

    public static void main(String []args) {
        PropertyConfigurator.configure("configs/log4j.properties");

        try {
            TestClassifier test = new TestClassifier();
            test.execute();
            logger.info(test.toString());
            Evaluation evaluation = test.getEvaluation();
            System.out.println("分类准确率：" + evaluation.pctCorrect());
            //System.out.println(evaluation.predictions());

        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Weka execute error: " + e);
        }

    }
}
